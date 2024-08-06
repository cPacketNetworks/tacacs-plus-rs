use futures::{FutureExt, TryFutureExt};
use tokio_util::compat::TokioAsyncWriteCompatExt;

use tacacs_plus::client::{AuthenticationType, ConnectionFactory, ContextBuilder, ResponseStatus};
use tacacs_plus::{Client, ClientError};
use tacacs_plus_protocol::DeserializeError;

#[async_std::test]
async fn chap_success() {
    let factory: ConnectionFactory<_> =
        Box::new(|| async_std::net::TcpStream::connect("localhost:5555").boxed());
    let mut client = Client::new(factory, Some("very secure key that is super secret"));

    let context = ContextBuilder::new("someuser").build();
    let response = client
        .authenticate(context, "something different", AuthenticationType::Chap)
        .await
        .expect("error completing CHAP authentication session");

    assert_eq!(
        response.status,
        ResponseStatus::Success,
        "authentication failed, full response: {response:?}"
    );
}

#[async_std::test]
async fn chap_failure() {
    let factory: ConnectionFactory<_> =
        Box::new(|| async_net::TcpStream::connect("localhost:5555").boxed());
    let mut client = Client::new(factory, Some("very secure key that is super secret"));

    let context = ContextBuilder::new("paponly").build();
    let response = client
        .authenticate(context, "pass-word", AuthenticationType::Chap)
        .await
        .expect("couldn't complete CHAP authentication session");

    assert_eq!(
        response.status,
        ResponseStatus::Failure,
        "CHAP authentication shouldn't succeed against paponly user"
    );
}

#[tokio::test]
async fn key_unconfigured() {
    let factory: ConnectionFactory<_> = Box::new(|| {
        tokio::net::TcpStream::connect("localhost:5555")
            .map_ok(TokioAsyncWriteCompatExt::compat_write)
            .boxed()
    });

    // don't configure a key
    // the type has to be annotated somewhere for generic reasons, since a bare None is ambiguous
    let mut client = Client::new(factory, None::<&[u8]>);

    let context = ContextBuilder::new("someuser").build();
    let error = client
        .authenticate(context, "something different", AuthenticationType::Chap)
        .await
        .expect_err("packet decoding should have failed without the right key configured");

    assert!(
        matches!(
            error,
            ClientError::InvalidPacketReceived(DeserializeError::IncorrectUnencryptedFlag)
        ),
        "got wrong error type; expected IncorrectUnencryptedFlag, but got {error:?}"
    );
}
