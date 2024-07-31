use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use tacacs_plus::client::{AuthStatus, SessionContextBuilder};
use tacacs_plus::Client;

#[tokio::main]
async fn main() {
    // NOTE: this assumes you have a TACACS+ server running already
    // there is a Dockerfile in assets/ which spins one up with the proper configuration

    let server = std::env::var("TACACS_SERVER").unwrap_or(String::from("localhost:5555"));
    let mut tac_client = Client::new_with_secret(
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
        b"this shouldn't be hardcoded",
    );

    let context = SessionContextBuilder::new()
        .user("someuser".to_owned())
        .build();
    let auth_result = tac_client.authenticate_pap_login(context, "hunter2").await;

    match auth_result {
        Ok(resp) => {
            if resp.status == AuthStatus::Pass {
                println!("Authentication successful!")
            } else {
                println!("Authentication failed. Full response: {:?}", resp);
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}
