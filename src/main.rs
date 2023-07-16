// Copyright (C) benaryorg <binary@benary.org>
//
// This software is licensed as described in the file COPYING, which
// you should have received as part of this distribution.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use ::
{
	std::
	{
		time::Duration,
		thread,
		fs::OpenOptions,
		os::unix::fs::OpenOptionsExt,
		path::PathBuf,
		io::
		{
			Read,
			Write,
		},
		process::
		{
			Command,
			Stdio,
			ExitCode,
			Termination,
		},
	},
	acme_micro::
	{
		Directory,
		DirectoryUrl,
	},
	clap::
	{
		Parser,
		Subcommand,
		ValueEnum,
	},
	anyhow::
	{
		Result,
		Context,
		bail,
		ensure,
	},
};

/// when to generate new files
#[derive(Clone,Hash,Debug,PartialEq,Eq,ValueEnum)]
enum Generation
{
	/// never generate the file, fail if it does not exist yet
	Never,
	/// always generate the file, overwrite existing files
	Always,
	/// generate the file if it does not exist yet
	Auto,
}

/// types of ACME challenges
#[derive(Clone,Hash,Debug,PartialEq,Eq,ValueEnum)]
enum Challenge
{
	/// use the dns-01 challenge
	Dns01,
}

mod error;
use error::*;

/// yet another acme-client - retrieves certificates via ACME
///
/// Leverages the 7 day period of validation to validate and certify independently.
/// Uses dnsmasq to pass the DNS challenge standalone.
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args
{
	/// filename for the account key
	#[clap(short, long, value_name = "ACCOUNT_FILE")]
	account: PathBuf,

	/// contact email for use with ACME
	#[clap(short, long, value_name = "EMAIL")]
	email: Vec<String>,

	/// when to generate a new account key
	#[clap(short, long, value_name = "WHEN", default_value = "auto")]
	generate: Generation,

	/// whether or not to accept the tos
	#[clap(short = 't', long)]
	accept_tos: bool,

	/// ACME directory used to query
	#[clap(short, long, value_name = "DIRECTORY", overrides_with = "letsencrypt", overrides_with = "letsencrypt_staging", required = true)]
	directory: Option<String>,

	/// use letsencrypt directory (overrides directory)
	#[clap(long, conflicts_with = "letsencrypt_staging")]
	letsencrypt: bool,

	/// use letsencrypt-staging directory (overrides directory)
	#[clap(long)]
	letsencrypt_staging: bool,

	#[clap(subcommand)]
	command: Action,
}

#[derive(Subcommand)]
enum Action
{
	/// issues a certificate if all domains are pre-validated
	Cert
	{
		/// domains to issue certificate for
		domain: Vec<String>,

		/// private key file
		#[clap(long, alias = "privkey", value_name = "FILE")]
		private_key: PathBuf,

		/// file to store the certificate, intermediate, and private key in
		#[clap(long, value_hint = clap::ValueHint::FilePath)]
		combined: Option<PathBuf>,

		/// file to store the intermediate in
		#[clap(long, value_name = "FILE")]
		intermediate: Option<PathBuf>,

		/// file to store the certificate and intermediate in
		#[clap(long, value_name = "FILE")]
		chain: Option<PathBuf>,

		/// file to store the certificate in
		#[clap(long, value_name = "FILE")]
		certificate: Option<PathBuf>,

		/// file to store the root certificate in
		#[clap(long, value_name = "FILE")]
		root: Option<PathBuf>,
	},
	/// re-validates all given domains by re-validating the challenge
	Cron
	{
		/// domains to re-validate
		domain: Vec<String>,

		/// which challenge to use
		#[clap(short = 't', long, value_name = "TYPE", default_value = "dns01")]
		challenge: Challenge,
	},
}

fn main() -> ExitCode
{
	let result = exec();

	// store the inner error if possible
	let alt_exit_code = match result
	{
		Err(ref err) => match err.downcast_ref::<ErrorKind>()
		{
			// override return code for transient errors (EAGAIN = 11)
			Some(ErrorKind::DnsmasqPremature(_)) => Some(ExitCode::from(11)),

			_ => None,
		},
		_ => None,
	};

	// this prints the error message
	let exit_code = result.report();

	// use the alternative exit code first
	alt_exit_code.unwrap_or(exit_code)
}

fn exec() -> Result<()>
{
	let args = Args::parse();

	if !args.accept_tos
	{
		bail!(ErrorKind::TermsOfService);
	}

	let directory = args.directory.as_ref().map(|dir| DirectoryUrl::Other(dir))
		.or_else(|| args.letsencrypt.then_some(DirectoryUrl::LetsEncrypt))
		.or_else(|| args.letsencrypt_staging.then_some(DirectoryUrl::LetsEncryptStaging))
		.expect("no directory url");
	eprintln!("using directory: {:?}", directory);
	let directory = Directory::from_url(directory).context(ErrorKind::InvalidDirectoryUrl)?;


	let email: Vec<String> = args.email.iter().map(|email| format!("mailto:{}", email)).collect();
	ensure!(!email.is_empty());

	let account =
	{
		let mut file = OpenOptions::new()
			.read(true)
			.write(args.generate != Generation::Never)
			.create(args.generate != Generation::Never)
			.truncate(args.generate == Generation::Always)
			.open(args.account).context(ErrorKind::AccountFileInaccessible)?;

		let mut key = String::new();
		file.read_to_string(&mut key)?;
		if let Ok(account) = directory.load_account(&key,email.clone())
		{
			account
		}
		else
		{
			let account = directory.register_account(email).context(ErrorKind::Registration)?;
			let privkey = account.acme_private_key_pem().context(ErrorKind::PrivateKeyWrite)?;
			file.write_all(privkey.as_bytes()).context(ErrorKind::PrivateKeyWrite)?;
			account
		}
	};

	match args.command
	{
		Action::Cron { domain, .. } =>
		{
			let (domain, alts) = domain.split_first().expect("no domains given");

			let order = account.new_order(domain, &alts.iter().map(|s| s.as_str()).collect::<Vec<_>>()).context(ErrorKind::OrderCreation)?;
			let auths = order.authorizations().context(ErrorKind::AuthorizationRetrieval)?;
			let challenges = auths.iter()
				.inspect(|auth|
				{
					eprintln!("auth for '{}' needs auth?: {}", auth.domain_name(), auth.need_challenge());
				})
				.map(|auth|
				{
					let challenge = auth.dns_challenge().ok_or(ErrorKind::BrokenChallenge)?;
					let proof = challenge.dns_proof().context(ErrorKind::Proof)?;
					Ok(( challenge
					, format!("_acme-challenge.{}.", auth.domain_name())
					, proof
					))
				})
				.collect::<Result<Vec<_>>>()?;

			let mut dnsmasq = Command::new("dnsmasq")
				.arg("--keep-in-foreground")
				.arg("--no-dhcp-interface=all")
				.arg("--no-ping")
				.arg("--no-resolv")
				.arg("--port=53")
				.args(
					challenges.iter()
						.map(|(_,domain,proof)| format!("--txt-record={},{}", domain, proof))
				)
				.stdout(Stdio::null())
				.stderr(Stdio::null())
				.stdin(Stdio::null())
				.spawn().context(ErrorKind::DnsmasqSpawn)?;

			eprintln!("starting dnsmasq");

			thread::sleep(Duration::from_secs(2));

			if let Some(status) = dnsmasq.try_wait().context(ErrorKind::DnsmasqWait)?
			{
				bail!(ErrorKind::DnsmasqPremature(status));
			}

			eprintln!("dnsmasq still running, starting challenges");

			let (ok,err): (Vec<_>,Vec<_>) = challenges.iter()
				.map(|(challenge,domain,_)| (domain,challenge.validate(Duration::from_secs(8))))
				.partition(|(_,res)| res.is_ok());

			//let _ = std::io::stdin().read_line(&mut String::new());

			// silently ignore error
			dnsmasq.kill().context(ErrorKind::DnsmasqKill)?;
			dnsmasq.wait().context(ErrorKind::DnsmasqWait)?;

			let failed = !err.is_empty();

			for (domain,_) in ok
			{
				eprintln!("ok for {}", domain);
			}

			for (domain,err) in err
			{
				eprintln!("err for {}: {}", domain, err.err().unwrap());
			}

			if failed
			{
				Err(ErrorKind::FailedChallenges.into())
			}
			else
			{
				Ok(())
			}
		},
		Action::Cert { domain, private_key, certificate, intermediate, chain, combined, root, } =>
		{
			let (domain, alts) = domain.split_first().expect("no domains given");

			let mut order = account.new_order(domain, &alts.iter().map(|s| s.as_str()).collect::<Vec<_>>()).context(ErrorKind::OrderCreation)?;
			let auths = order.authorizations().context(ErrorKind::AuthorizationRetrieval)?;
			let missing = auths.iter().filter(|auth| auth.need_challenge()).map(|auth| auth.domain_name().to_string()).collect::<Vec<_>>();
			if !missing.is_empty()
			{
				bail!(ErrorKind::MissingAuthorizations(missing));
			}

			order.refresh().context(ErrorKind::OrderRefresh)?;
			ensure!(order.is_validated(), ErrorKind::OrderValidation);

			match order.confirm_validations()
			{
				None => bail!(ErrorKind::OrderValidation),
				Some(csr) =>
				{
					let order =
					{
						let mut file = OpenOptions::new()
							.read(true)
							.write(false)
							.create(false)
							.truncate(false)
							.open(private_key).context(ErrorKind::AccountFileInaccessible)?;

						let mut key = String::new();
						file.read_to_string(&mut key)?;
						csr.finalize(&key,Duration::from_secs(8)).context(ErrorKind::OrderFinalize)?
					};
					let response = order.download_cert().context(ErrorKind::CertDownload)?;

					let parts = response.certificate().split("\n\n").collect::<Vec<_>>();

					ensure!(parts.len() == 3, ErrorKind::BogusCertificateParts);
					let parts_cert = parts[0];
					let parts_intermediate = parts[1];
					let parts_root = parts[2];
					let parts_key = response.private_key();

					let open_file = |filename: PathBuf|
					{
						OpenOptions::new()
							.read(false)
							.write(true)
							.create(true)
							.truncate(true)
							.mode(0o600)
							.open(filename.as_path()).with_context(|| ErrorKind::OutputFileInaccessible(filename.to_string_lossy().to_string()))
					};

					if let Some(filename) = certificate
					{
						let mut file = open_file(filename)?;
						writeln!(&mut file, "{}", parts_cert)?;
					}
					if let Some(filename) = intermediate
					{
						let mut file = open_file(filename)?;
						writeln!(&mut file, "{}", parts_intermediate)?;
					}
					if let Some(filename) = chain
					{
						let mut file = open_file(filename)?;
						writeln!(&mut file, "{}\n{}", parts_cert, parts_intermediate)?;
					}
					if let Some(filename) = combined
					{
						let mut file = open_file(filename)?;
						writeln!(&mut file, "{}\n{}\n{}", parts_cert, parts_intermediate, parts_key)?;
					}
					if let Some(filename) = root
					{
						let mut file = open_file(filename)?;
						writeln!(&mut file, "{}", parts_root)?;
					}
				},
			}

			Ok(())
		},
	}
}

