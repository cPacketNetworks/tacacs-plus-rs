use async_net::TcpStream;
use futures::FutureExt;

use tacacs_plus::client::{AuthenticationType, ConnectionFactory, ContextBuilder, ResponseStatus};
use tacacs_plus::Client;

#[test]
fn main() {
    futures::executor::block_on(do_auth());
}

async fn do_auth() {
    let factory: ConnectionFactory<_> = Box::new(|| TcpStream::connect("localhost:5555").boxed());
    let mut client = Client::new(factory, Some("very secure key that is super secret"));

    let context = ContextBuilder::new("someuser").build();
    let response = client
        .authenticate(context, "something different", AuthenticationType::Chap)
        .await
        .expect("error completing CHAP authentication session");

    assert!(
        response.status == ResponseStatus::Success,
        "authentication failed, full response: {response:?}"
    );
}
