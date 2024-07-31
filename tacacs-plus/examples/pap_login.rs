use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use tacacs_plus::protocol::authentication::Status;
use tacacs_plus::protocol::UserInformation;
use tacacs_plus::Client;

#[tokio::main]
async fn main() {
    // NOTE: this assumes you have a TACACS+ server running already
    // there is a Dockerfile in assets/examples which spins one up with the proper configuration

    let server = std::env::var("TACACS_SERVER").unwrap_or(String::from("localhost:5555"));
    let mut tac_client = Client::new_with_secret(
        Box::new(move || {
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

    let user_info = UserInformation::new_with_user("someuser").unwrap();
    let auth_result = tac_client
        .authenticate_pap_login(user_info, "hunter2", Default::default())
        .await;

    match auth_result {
        Ok(packet) => {
            if packet.body().status == Status::Pass {
                println!("Authentication successful!")
            } else {
                println!("Reply status was {:?}, not pass", packet.body().status);
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}
