use ::thiserror::Error;

#[derive(Error, Debug)]
pub enum ErrorKind
{
	#[error("invalid directory url provided")]
	InvalidDirectoryUrl,
    #[error("account file is inaccessible")]
    AccountFileInaccessible,
    #[error("registration with acme directory failed")]
    Registration,
    #[error("new private key could not be written to disk")]
    PrivateKeyWrite,
    #[error("creation of new order failed")]
    OrderCreation,
    #[error("cannot retrieve required authorizations")]
    AuthorizationRetrieval,
    #[error("authorization does not contain challenge, upstream has no docs on this")]
    BrokenChallenge,
    #[error("retrieving the proof for the challenge has failed")]
    Proof,
    #[error("failed to spawn dnsmasq")]
    DnsmasqSpawn,
    #[error("failed to kill dnsmasq")]
    DnsmasqKill,
    #[error("failed to wait for dnsmasq")]
    DnsmasqWait,
    #[error("dnsmasq did exit prematurely with an exit code: {0:?}")]
    DnsmasqPremature(::std::process::ExitStatus),
    #[error("some challenges have failed")]
    FailedChallenges,
    #[error("domains are missing authorization: {0:?}")]
    MissingAuthorizations(Vec<String>),
    #[error("could not refresh order")]
    OrderRefresh,
    #[error("order could not be validated")]
    OrderValidation,
    #[error("order could not be finalized")]
    OrderFinalize,
    #[error("certificate could not be downloaded")]
    CertDownload,
    #[error("the certificate received was non-trivial to parse, bailing")]
    BogusCertificateParts,
    #[error("output file '{0}' is inaccessible")]
    OutputFileInaccessible(String),
}

