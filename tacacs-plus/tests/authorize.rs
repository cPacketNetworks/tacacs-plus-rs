use async_net::TcpStream;
use futures::FutureExt;

use tacacs_plus::client::ResponseStatus;
use tacacs_plus::client::{ConnectionFactory, ContextBuilder};
use tacacs_plus::Client;
use tacacs_plus_protocol::ArgumentOwned;

#[test]
fn authorize_success() {
    futures::executor::block_on(do_authorization());
}

async fn do_authorization() {
    let connection_factory: ConnectionFactory<_> =
        Box::new(|| TcpStream::connect("localhost:5555").boxed());

    let mut client = Client::new(
        connection_factory,
        Some("very secure key that is super secret"),
    );

    let arguments = vec![
        ArgumentOwned {
            name: "service".to_owned(),
            value: "authorizeme".to_owned(),
            required: true,
        },
        ArgumentOwned {
            name: "thing".to_owned(),
            // the shrubbery TACACS+ daemon replaces optional arguments whose values are different
            // from the server config with their configured values
            // if this argument is instead changed to required, that doesn't happen
            value: "this will be replaced".to_owned(),
            required: false,
        },
    ];

    let context = ContextBuilder::new("someuser").build();
    let response = client
        .authorize(context, arguments)
        .await
        .expect("error when completing authorization session");

    assert_eq!(
        response.status,
        ResponseStatus::Success,
        "authorization failed, full response: {response:?}"
    );

    // ensure argument was properly replaced
    assert!(response.arguments.contains(&ArgumentOwned {
        name: "thing".to_owned(),
        value: "not important".to_owned(),
        required: false
    }));

    for argument in response.arguments {
        let required_str = if argument.required {
            "required"
        } else {
            "optional"
        };

        println!("{} = {} ({})", argument.name, argument.value, required_str);
    }
}

#[test]
fn authorize_fail() {
    futures::executor::block_on(authorization_fail());
}

async fn authorization_fail() {
    let connection_factory: ConnectionFactory<_> =
        Box::new(|| TcpStream::connect("localhost:5555").boxed());

    let mut client = Client::new(
        connection_factory,
        Some("very secure key that is super secret"),
    );

    let arguments = vec![
        ArgumentOwned {
            name: "service".to_owned(),
            value: "authorizeme".to_owned(),
            required: true,
        },
        // the Shrubbery TACACS+ daemon denies authorization requests where mandatory arguments don't match their configured values
        ArgumentOwned {
            name: "number".to_owned(),
            value: "3".to_owned(),
            required: true,
        },
    ];

    let context = ContextBuilder::new("someuser").build();
    let response = client
        .authorize(context, arguments)
        .await
        .expect("couldn't complete authorization session");

    assert_eq!(
        response.status,
        ResponseStatus::Failure,
        "authorization succeeded when it shouldn't have, full response: {response:?}"
    );
}
