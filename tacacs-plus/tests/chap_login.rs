use futures::{FutureExt, TryFutureExt};
use tokio_util::compat::TokioAsyncWriteCompatExt;

use tacacs_plus::{AuthenticationType, ConnectionFactory, ContextBuilder, ResponseStatus};
use tacacs_plus::{Client, ClientError};
use tacacs_plus_protocol::DeserializeError;

mod common;

#[async_std::test]
async fn chap_success() {
    let address = common::get_server_address();
    let factory: ConnectionFactory<_> =
        Box::new(move || async_std::net::TcpStream::connect(address.clone()).boxed());
    let client = Client::new(factory, Some(common::SECRET_KEY));

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
    let address = common::get_server_address();
    let factory: ConnectionFactory<_> =
        Box::new(move || async_net::TcpStream::connect(address.clone()).boxed());
    let client = Client::new(factory, Some(common::SECRET_KEY));

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
    let address = common::get_server_address();
    let factory: ConnectionFactory<_> = Box::new(move || {
        tokio::net::TcpStream::connect(address.clone())
            .map_ok(TokioAsyncWriteCompatExt::compat_write)
            .boxed()
    });

    // don't configure a key
    // the type has to be annotated somewhere for generic reasons, since a bare None is ambiguous
    let client = Client::new(factory, None::<&[u8]>);

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
