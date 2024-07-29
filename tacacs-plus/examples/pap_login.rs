use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use tacacs_plus::protocol::authentication::Status;
use tacacs_plus::protocol::PrivilegeLevel;
use tacacs_plus::Client;

#[tokio::main]
async fn main() {
    // NOTE: this assumes you have a TACACS+ server running already
    // there is a Dockerfile in assets/examples which spins one up with the proper configuration
    let stream = TcpStream::connect("localhost:5555").await.unwrap();

    // tokio has its own Async{Read,Write} traits (as opposed to those in futures) so we need a compatibility shim
    let mut tac_client =
        Client::new_with_secret(stream.compat_write(), b"this shouldn't be hardcoded");

    let auth_result = tac_client
        .authenticate_pap_login("someuser", "hunter2", PrivilegeLevel::new(0).unwrap())
        .await;

    match auth_result {
        Ok(packet) => {
            if packet.body().status == Status::Pass {
                println!("Authentication successful!")
            } else {
                println!("Authentication request denied")
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}
