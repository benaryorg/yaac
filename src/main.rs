use ::
{
	std::
	{
		time::Duration,
		thread,
		fs::OpenOptions,
		os::unix::fs::OpenOptionsExt,
		io::
		{
			Read,
			Write,
		},
		process::
		{
			Command,
			Stdio,
		},
	},
	acme_micro::
	{
		Directory,
		DirectoryUrl,
	},
	clap::
	{
		Arg,
		ArgGroup,
		SubCommand,
		app_from_crate,
		crate_authors,
		crate_description,
		crate_name,
		crate_version,
		arg_enum
	},
	anyhow::
	{
		Result,
		Context,
		bail,
		ensure,
	},
};

arg_enum!
{
	#[derive(Hash,Debug,PartialEq,Eq)]
	enum Generation
	{
		Never,
		Always,
		Auto,
	}
}

arg_enum!
{
	#[derive(Hash,Debug,PartialEq,Eq)]
	enum Challenge
	{
		Dns01,
	}
}

mod error;
use error::*;

fn main() -> Result<()>
{
	let matches = app_from_crate!()
		.setting(clap::AppSettings::SubcommandRequiredElseHelp)
		.arg(Arg::with_name("account")
			.short("a")
			.long("account")
			.help("filename for the account key")
			.takes_value(true)
			.value_name("ACCOUNT_FILE")
			.multiple(false)
			.required(true)
		)
		.arg(Arg::with_name("email")
			.short("e")
			.long("email")
			.help("contact email for use with ACME")
			.takes_value(true)
			.value_name("EMAIL")
			.multiple(true)
			.required(true)
			.use_delimiter(false)
			.number_of_values(1)
		)
		.arg(clap::Arg::with_name("generate")
			.short("g")
			.long("generate")
			.value_name("WHEN")
			.help("when to generate a new account key")
			.possible_values(&Generation::variants())
			.default_value("auto")
			.case_insensitive(true)
		)
		.arg(Arg::with_name("accept-tos")
			.short("t")
			.long("accept-tos")
			.help("whether or not to accept the tos, setting this at all regardless of value does indicate agreement")
			.takes_value(false)
			.multiple(false)
			.required(true)
		)
		.group(ArgGroup::with_name("dir")
			.required(true)
			.arg("directory")
			.arg("letsencrypt-staging")
			.arg("letsencrypt")
		)
		.arg(Arg::with_name("directory")
			.short("d")
			.long("directory")
			.help("ACME directory used to query")
			.takes_value(true)
			.value_name("DIRECTORY")
			.multiple(false)
			.global(true)
		)
		.arg(Arg::with_name("letsencrypt-staging")
			.short("s")
			.long("letsencrypt-staging")
			.alias("staging")
			.help("use the Let's Encrypt staging directory")
			.takes_value(false)
			.multiple(false)
			.global(true)
		)
		.arg(Arg::with_name("letsencrypt")
			.short("l")
			.long("letsencrypt")
			.help("use the Let's Encrypt production directory")
			.takes_value(false)
			.multiple(false)
			.global(true)
		)
		.arg(Arg::with_name("loglevel")
			.short("v")
			.long("loglevel")
			.help("loglevel to be used, if not specified uses env_logger's auto-detection")
			.takes_value(true)
			.value_name("LOGLEVEL")
			.multiple(false)
			.global(true)
		)
		.subcommand(SubCommand::with_name("cert")
			.about("issues a certificate if all domains are pre-validated")
			.arg(Arg::with_name("domain")
				.value_name("DOMAIN")
				.help("domains to re-validate")
				.takes_value(true)
				.multiple(true)
				.required(true)
				.use_delimiter(false)
			)
			.arg(clap::Arg::with_name("challenge")
				.short("t")
				.long("challenge")
				.value_name("TYPE")
				.help("which challenge to use")
				.possible_values(&Challenge::variants())
				.default_value("dns01")
				.case_insensitive(true)
			)
			.arg(Arg::with_name("private-key")
				.short("p")
				.long("private-key")
				.alias("privkey")
				.help("private key file")
				.takes_value(true)
				.value_name("FILE")
				.multiple(false)
				.required(true)
			)
			.arg(Arg::with_name("combined")
				.short("b")
				.long("combined")
				.help("file to store the certificate, intermediate, and private key in")
				.takes_value(true)
				.value_name("FILE")
				.multiple(false)
			)
			.arg(Arg::with_name("intermediate")
				.short("i")
				.long("intermediate")
				.help("file to store the intermediate in")
				.takes_value(true)
				.value_name("FILE")
				.multiple(false)
			)
			.arg(Arg::with_name("chain")
				.long("chain")
				.help("file to store the certificate and intermediate in")
				.takes_value(true)
				.value_name("FILE")
				.multiple(false)
			)
			.arg(Arg::with_name("certificate")
				.short("c")
				.long("certificate")
				.alias("cert")
				.help("file to store the certificate in")
				.takes_value(true)
				.value_name("FILE")
				.multiple(false)
			)
			.arg(Arg::with_name("root")
				.short("r")
				.long("root")
				.help("file to store the root certificate in")
				.takes_value(true)
				.value_name("FILE")
				.multiple(false)
			)
		)
		.subcommand(SubCommand::with_name("cron")
			.about("re-validates all given domains by re-validating the challenge")
			.arg(Arg::with_name("domain")
				.value_name("DOMAIN")
				.help("domains to re-validate")
				.takes_value(true)
				.multiple(true)
				.required(true)
				.use_delimiter(false)
			)
			.arg(clap::Arg::with_name("challenge")
				.short("t")
				.long("challenge")
				.value_name("TYPE")
				.help("which challenge to use")
				.possible_values(&Challenge::variants())
				.default_value("dns01")
				.case_insensitive(true)
			)
		)
		.get_matches();

	let directory = matches.value_of("directory").map(|dir| DirectoryUrl::Other(dir))
		.or_else(|| matches.is_present("letsencrypt").then(|| DirectoryUrl::LetsEncrypt))
		.or_else(|| matches.is_present("letsencrypt-staging").then(|| DirectoryUrl::LetsEncryptStaging))
		.map(Directory::from_url)
		.expect("no directory url").context(ErrorKind::InvalidDirectoryUrl)?;

	let email: Vec<String> = matches.values_of("email").expect("no email given").map(|email| format!("mailto:{}", email)).collect();
	ensure!(!email.is_empty());

	let generate = clap::value_t_or_exit!(matches.value_of("generate"),Generation);
	let account =
	{
		let filename = matches.value_of("account").expect("no account file given");
		let mut file = OpenOptions::new()
			.read(true)
			.write(generate != Generation::Never)
			.create(generate != Generation::Never)
			.truncate(generate == Generation::Always)
			.open(filename).context(ErrorKind::AccountFileInaccessible)?;

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

	match matches.subcommand()
	{
		("cron",Some(matches)) =>
		{
			let (domain, alts) =
			{
				let mut iter = matches.values_of("domain").expect("no domain given");
				let first = iter.next().expect("no domains given");
				(first,iter.collect::<Vec<_>>())
			};

			let order = account.new_order(domain,&alts).context(ErrorKind::OrderCreation)?;
			let auths = order.authorizations().context(ErrorKind::AuthorizationRetrieval)?;
			let challenges = auths.into_iter()
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
		("cert",Some(matches)) =>
		{
			let (domain, alts) =
			{
				let mut iter = matches.values_of("domain").expect("no domain given");
				let first = iter.next().expect("no domains given");
				(first,iter.collect::<Vec<_>>())
			};

			let mut order = account.new_order(domain,&alts).context(ErrorKind::OrderCreation)?;
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
						let keyfile = matches.value_of("private-key").unwrap();

						let mut file = OpenOptions::new()
							.read(true)
							.write(false)
							.create(false)
							.truncate(false)
							.open(keyfile).context(ErrorKind::AccountFileInaccessible)?;

						let mut key = String::new();
						file.read_to_string(&mut key)?;
						csr.finalize(&key,Duration::from_secs(8)).context(ErrorKind::OrderFinalize)?
					};
					let response = order.download_cert().context(ErrorKind::CertDownload)?;

					let parts = response.certificate().split("\n\n").collect::<Vec<_>>();

					ensure!(parts.len() == 3, ErrorKind::BogusCertificateParts);
					let cert = parts[0];
					let intermediate = parts[1];
					let root = parts[2];
					let key = response.private_key();

					let open_file = |filename: &str|
					{
						OpenOptions::new()
							.read(false)
							.write(true)
							.create(true)
							.truncate(true)
							.mode(0o600)
							.open(filename).context(ErrorKind::OutputFileInaccessible(filename.to_string()))
					};

					if let Some(filename) = matches.value_of("certificate")
					{
						let mut file = open_file(filename)?;
						writeln!(&mut file,"{}", cert)?;
					}
					if let Some(filename) = matches.value_of("intermediate")
					{
						let mut file = open_file(filename)?;
						writeln!(&mut file,"{}", intermediate)?;
					}
					if let Some(filename) = matches.value_of("chain")
					{
						let mut file = open_file(filename)?;
						writeln!(&mut file,"{}\n{}", cert, intermediate)?;
					}
					if let Some(filename) = matches.value_of("combined")
					{
						let mut file = open_file(filename)?;
						writeln!(&mut file,"{}\n{}\n{}", cert, intermediate, key)?;
					}
					if let Some(filename) = matches.value_of("root")
					{
						let mut file = open_file(filename)?;
						writeln!(&mut file,"{}", root)?;
					}
				},
			}

			Ok(())
		},
		_ => unreachable!(),
	}
}

