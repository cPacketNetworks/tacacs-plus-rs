use common::get_server_address;
use futures::{FutureExt, TryFutureExt};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use tacacs_plus::Client;
use tacacs_plus::ConnectionFactory;
use tacacs_plus::{AuthenticationType, ContextBuilder, ResponseStatus};

mod common;

#[tokio::test]
async fn pap_success() {
    // NOTE: this assumes you have a TACACS+ server running already
    // test-assets/run-client-tests.sh in the repo root will set that up for you assuming you have Docker installed

    let address = common::get_server_address();
    let tac_client = Client::new(
        Box::new(move || {
            TcpStream::connect(address.clone())
                // tokio has its own AsyncRead/AsyncWrite traits, so we need a compatibility shim
                // to be able to use its types
                .map_ok(TokioAsyncWriteCompatExt::compat_write)
                .boxed()
        }),
        Some(common::SECRET_KEY),
    );

    let context = ContextBuilder::new("someuser").build();

    let response = tac_client
        .authenticate(context, "hunter2", AuthenticationType::Pap)
        .await
        .expect("error completing authentication session");

    assert_eq!(
        response.status,
        ResponseStatus::Success,
        "authentication failed, full response: {response:?}"
    );
}

#[tokio::test]
async fn pap_follow_failure() {
    let address = get_server_address();
    let factory: ConnectionFactory<_> = Box::new(move || {
        TcpStream::connect(address.clone())
            .map_ok(TokioAsyncWriteCompatExt::compat_write)
            .boxed()
    });

    let client = Client::new(factory, Some(common::SECRET_KEY));

    let context = ContextBuilder::new("followme").build();
    let response = client
        .authenticate(context, "outbound", AuthenticationType::Pap)
        .await
        .expect("authentication session couldn't be completed");

    assert_eq!(
        response.status,
        ResponseStatus::Failure,
        "follow response should be treated as a failure"
    );
}
