use async_net::TcpStream;
use futures::FutureExt;

use tacacs_plus::client::{AuthenticationType, ConnectionFactory, ContextBuilder, ResponseStatus};
use tacacs_plus::Client;

fn main() {
    futures::executor::block_on(do_auth());
}

async fn do_auth() {
    let factory: ConnectionFactory<_> = Box::new(|| TcpStream::connect("localhost:5555").boxed());
    let mut client = Client::new(factory, Some("this shouldn't be hardcoded"));

    let context = ContextBuilder::new("someuser").build();
    let response = client
        .authenticate(context, "something different", AuthenticationType::Chap)
        .await;

    match response {
        Ok(resp) => {
            if resp.status == ResponseStatus::Success {
                println!("Authentication successful!")
            } else {
                println!("Authentication failed. Full response: {resp:?}");
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}
