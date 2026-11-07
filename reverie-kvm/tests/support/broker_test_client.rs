// No fork/bootstrap occurs in this module. The selected libtest worker only
// adopts a channel created by the ordinary-main launcher before libtest exists.
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::sync::OnceLock;

use super::broker_test_protocol::CHANNEL_ENV;
use super::broker_test_protocol::CHILD_ENV;
use super::broker_test_protocol::NONCE_ENV;
use super::native_exit_broker::BrokerClient;
use super::native_exit_broker::ExecClientFailure;

// A failed authentication retains the exact duplicated owner until this one-test
// process exits natively. No guest, native fixture or backend has started yet.
struct AttachFailure {
    message: String,
    retained: Option<ExecClientFailure>,
}

static CLIENT: OnceLock<Result<BrokerClient, AttachFailure>> = OnceLock::new();

pub fn attach(test: &str) {
    assert!(super::broker_test_protocol::selected(test));
    assert_eq!(std::env::var(CHILD_ENV).as_deref(), Ok(test));
    let result = CLIENT.get_or_init(adopt);
    if let Err(failure) = result {
        // Reading the retained owner is diagnostic, never evidence of authority.
        panic!(
            "broker client setup failed before test body: {}; retained_fd={:?}; retained_rights={}",
            failure.message,
            failure
                .retained
                .as_ref()
                .and_then(|f| f.channel.as_ref())
                .map(AsRawFd::as_raw_fd),
            failure
                .retained
                .as_ref()
                .map_or(0, |f| f.retained_rights.len())
        );
    }
}

pub fn client() -> BrokerClient {
    match CLIENT
        .get()
        .expect("selected child must attach before its test body")
    {
        Ok(client) => client.clone(),
        Err(_) => panic!("failed broker attachment cannot supply a client"),
    }
}

fn adopt() -> Result<BrokerClient, AttachFailure> {
    let without_owner = |message: String| AttachFailure {
        message,
        retained: None,
    };
    let source: i32 = std::env::var(CHANNEL_ENV)
        .map_err(|e| without_owner(e.to_string()))?
        .parse::<i32>()
        .map_err(|e| without_owner(e.to_string()))?;
    if source < 3 {
        return Err(without_owner(
            "inherited channel must not alias stdio".into(),
        ));
    }
    // Reject non-sockets before duplicating an arbitrary ambient descriptor:
    // even an extra close can invoke a filesystem's .flush callback.
    for (option, expected) in [
        (libc::SO_TYPE, libc::SOCK_SEQPACKET),
        (libc::SO_DOMAIN, libc::AF_UNIX),
    ] {
        let mut value = 0i32;
        let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                source,
                libc::SOL_SOCKET,
                option,
                (&mut value as *mut i32).cast(),
                &mut length,
            )
        };
        if result != 0 || length as usize != std::mem::size_of::<i32>() || value != expected {
            return Err(without_owner(
                "inherited channel is not an AF_UNIX seqpacket socket".into(),
            ));
        }
    }
    let encoded = std::env::var(NONCE_ENV).map_err(|e| without_owner(e.to_string()))?;
    if encoded.len() != 64 || !encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(without_owner("invalid broker nonce encoding".into()));
    }
    let mut nonce = [0u8; 32];
    for (i, value) in nonce.iter_mut().enumerate() {
        *value = u8::from_str_radix(&encoded[i * 2..i * 2 + 2], 16)
            .map_err(|e| without_owner(e.to_string()))?;
    }
    // An environment integer is not an OwnedFd. Duplicate it to acquire a new
    // real owner, and authenticate that owner before changing/closing the source.
    let duplicate = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(without_owner(std::io::Error::last_os_error().to_string()));
    }
    let channel = unsafe { OwnedFd::from_raw_fd(duplicate) };
    // The core receives the registered broker's nonce before sending any secret;
    // a fake endpoint cannot grant authority by echoing a nonce from its client.
    let client = BrokerClient::adopt_exec_channel(channel, nonce).map_err(
        |failure: ExecClientFailure| AttachFailure {
            message: failure.cause.to_string(),
            retained: Some(failure),
        },
    )?;
    // Successful authentication proves the exact dedicated one-use launcher
    // session. The original inherited endpoint has no Rust owner in this fresh
    // libtest image. It must not leak into subsequent native fixture execs.
    // Linux close is not retried: retry could close a reused descriptor.
    if unsafe { libc::close(source) } != 0 {
        return Err(without_owner(format!(
            "authenticated inherited channel close: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(client)
}
