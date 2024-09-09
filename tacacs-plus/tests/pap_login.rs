use std::time::Duration;

use futures::{FutureExt, TryFutureExt};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

use tacacs_plus::Client as TacacsClient;
use tacacs_plus::{AuthenticationType, ContextBuilder, ResponseStatus};

mod common;

type Client = TacacsClient<Compat<TcpStream>>;

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

    attempt_pap_login(&tac_client, "someuser".to_owned(), "hunter2").await;
}

// this test is ignored since it takes a bit to run & requires specific actions to run alongside the test (restarting server)
#[tokio::test]
#[ignore]
async fn connection_reestablishment() {
    let address = common::get_server_address();
    let client = Client::new(
        Box::new(move || {
            TcpStream::connect(address.clone())
                .map_ok(TokioAsyncWriteCompatExt::compat_write)
                .boxed()
        }),
        Some(common::SECRET_KEY),
    );

    let user = String::from("paponly");
    let password = "pass-word";
    attempt_pap_login(&client, user.clone(), password).await;

    // restart server container
    if let Ok(container_name) = std::env::var("SERVER_CONTAINER") {
        restart_server_container(container_name).await;
    }

    // sleep for a bit to allow server time to start back up
    tokio::time::sleep(Duration::from_millis(500)).await;

    // try logging in after server restart to ensure connection is reestablished
    attempt_pap_login(&client, user, password).await;
}

async fn attempt_pap_login(client: &Client, user: String, password: &str) {
    let context = ContextBuilder::new(user).build();
    let response = client
        .authenticate(context, password, AuthenticationType::Pap)
        .await
        .expect("error completing authentication session");

    assert_eq!(
        response.status,
        ResponseStatus::Success,
        "authentication failed, full response: {response:?}"
    );
}

async fn restart_server_container(name: String) {
    let docker_command = std::env::var("docker").unwrap_or_else(|_| "docker".to_owned());

    let status = tokio::process::Command::new(docker_command)
        .args(["restart", &name])
        .stdout(std::process::Stdio::null())
        .status()
        .await
        .expect("couldn't get exit status of server container restart command");

    assert!(status.success(), "bad exit status: {status}");
}
