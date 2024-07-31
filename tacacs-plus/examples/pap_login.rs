use std::future::Future;
use std::pin::Pin;

use tacacs_plus::client::ConnectionFactory;
use tokio::io;
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

use tacacs_plus::protocol::authentication::Status;
use tacacs_plus::protocol::UserInformation;
use tacacs_plus::Client;

pub type ConnectionFactory2<S> = Box<dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<S>>>>>;

// async closures are still unstable, so we have to manage with this :)
fn stream_factory() -> Pin<Box<dyn Future<Output = io::Result<Compat<TcpStream>>>>> {
    Box::pin(async {
        TcpStream::connect("localhost:5555")
            .await
            .map(TokioAsyncWriteCompatExt::compat_write)
    })
}

fn stream_factory2(server: String) -> Pin<Box<dyn Future<Output = io::Result<Compat<TcpStream>>>>> {
    Box::pin(async move {
        TcpStream::connect(server)
            .await
            .map(TokioAsyncWriteCompatExt::compat_write)
    })
}

#[tokio::main]
async fn main() {
    // NOTE: this assumes you have a TACACS+ server running already
    // there is a Dockerfile in assets/examples which spins one up with the proper configuration

    let server = "localhost:5555";
    let server_owned = server.to_owned();
    let factory: ConnectionFactory2<_> = Box::new(move || {
        Box::pin(async move {
            TcpStream::connect(server)
                .await
                .map(TokioAsyncWriteCompatExt::compat_write)
        })
    });
    let factory2: ConnectionFactory2<_> = Box::new(stream_factory);
    let factory3: ConnectionFactory2<_> = Box::new(move || stream_factory2(server_owned.clone()));
    let mut tac_client =
        Client::new_with_secret(Box::new(stream_factory), b"this shouldn't be hardcoded");

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
