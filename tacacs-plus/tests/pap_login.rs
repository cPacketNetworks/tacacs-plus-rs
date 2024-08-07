use futures::{FutureExt, TryFutureExt};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use tacacs_plus::Client;
use tacacs_plus::ConnectionFactory;
use tacacs_plus::{AuthenticationType, ContextBuilder, ResponseStatus};

#[tokio::test]
async fn pap_success() {
    // NOTE: this assumes you have a TACACS+ server running already
    // test-assets/run-client-tests.sh in the repo root will set that up for you assuming you have Docker installed

    let server = std::env::var("TACACS_SERVER").unwrap_or(String::from("localhost:5555"));
    let mut tac_client = Client::new(
        Box::new(move || {
            // closures can also capture external variables
            let server = server.clone();

            Box::pin(async move {
                TcpStream::connect(server)
                    .await
                    // tokio has its own AsyncRead/AsyncWrite traits, so we need a compatibility shim
                    // to be able to use its types
                    .map(TokioAsyncWriteCompatExt::compat_write)
            })
        }),
        Some("very secure key that is super secret"),
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
    let factory: ConnectionFactory<_> = Box::new(|| {
        TcpStream::connect(("localhost", 5555))
            .map_ok(TokioAsyncWriteCompatExt::compat_write)
            .boxed()
    });

    let mut client = Client::new(factory, Some("very secure key that is super secret"));

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
