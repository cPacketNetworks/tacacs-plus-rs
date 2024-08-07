use async_std::net::TcpStream;
use futures::FutureExt;

use tacacs_plus::Client;
use tacacs_plus::ResponseStatus;
use tacacs_plus::{AuthenticationMethod, ConnectionFactory, ContextBuilder};
use tacacs_plus_protocol::ArgumentOwned;

#[async_std::test]
async fn authorize_success() {
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

    // the Shrubbery daemon returns all arguments sent & set server side
    // if any values are replaced (as is the case here)
    assert_eq!(
        response.arguments,
        [
            ArgumentOwned {
                name: "service".to_owned(),
                value: "authorizeme".to_owned(),
                required: true,
            },
            ArgumentOwned {
                name: "thing".to_owned(),
                value: "not important".to_owned(),
                required: false
            },
            // arguments set on server are appended to the provided list (I believe)
            ArgumentOwned {
                name: "number".to_owned(),
                value: "42".to_owned(),
                required: true,
            },
        ]
    );
}

#[async_std::test]
async fn authorize_fail_wrong_argument_value() {
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

#[async_std::test]
async fn guest_authorize() {
    let factory: ConnectionFactory<TcpStream> =
        Box::new(|| TcpStream::connect("localhost:5555").boxed());
    let mut client = Client::new(factory, Some("very secure key that is super secret"));

    let arguments = vec![ArgumentOwned {
        name: "service".to_owned(),
        value: "guest".to_owned(),
        required: true,
    }];

    let context = ContextBuilder::new("")
        .auth_method(AuthenticationMethod::Guest)
        .build();
    let response = client
        .authorize(context, arguments)
        .await
        .expect("couldn't complete authorization session");

    assert_eq!(response.status, ResponseStatus::Success);
    assert_eq!(
        response.arguments,
        [
            ArgumentOwned {
                name: "priv-lvl".to_owned(),
                value: "0".to_owned(),
                required: true
            },
            ArgumentOwned {
                name: "authenticated".to_owned(),
                value: "false".to_owned(),
                required: true
            }
        ]
    );
}
