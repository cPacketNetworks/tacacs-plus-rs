use async_net::TcpStream;
use futures::FutureExt;

use tacacs_plus::client::{AuthenticationType, ConnectionFactory, ContextBuilder, ResponseStatus};
use tacacs_plus::Client;

#[test]
fn chap_success() {
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

    assert_eq!(
        response.status,
        ResponseStatus::Success,
        "authentication failed, full response: {response:?}"
    );
}

#[test]
fn chap_failure() {
    futures::executor::block_on(fail_chap())
}

async fn fail_chap() {
    let factory: ConnectionFactory<_> = Box::new(|| TcpStream::connect("localhost:5555").boxed());
    let mut client = Client::new(factory, Some("very secure key that is super secret"));

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

#[test]
fn key_unconfigured() {
    futures::executor::block_on(no_key())
}

async fn no_key() {
    let factory: ConnectionFactory<_> = Box::new(|| TcpStream::connect("localhost:5555").boxed());

    // don't configure a key
    // the type has to be annotated somewhere for generic reasons, since a bare None is ambiguous
    let mut client = Client::new(factory, None::<&[u8]>);

    let context = ContextBuilder::new("someuser").build();
    client
        .authenticate(context, "something different", AuthenticationType::Chap)
        .await
        .expect_err("packet decoding should have failed without the right key configured");
}
