use async_std::net::TcpStream;
use futures::FutureExt;

use tacacs_plus::Argument;
use tacacs_plus::Client;
use tacacs_plus::{AuthenticationMethod, ConnectionFactory, ContextBuilder, ResponseStatus};

mod common;

#[async_std::test]
async fn authorize_success() {
    let address = common::get_server_address();
    let connection_factory: ConnectionFactory<_> =
        Box::new(move || TcpStream::connect(address.clone()).boxed());

    let client = Client::new(connection_factory, Some(common::SECRET_KEY));

    let arguments = vec![
        Argument::new(
            "service".try_into().unwrap(),
            "authorizeme".try_into().unwrap(),
            true,
        )
        .unwrap(),
        Argument::new(
            "thing".try_into().unwrap(),
            // the shrubbery TACACS+ daemon replaces optional arguments whose values are different
            // from the server config with their configured values
            // if this argument is instead changed to required, that doesn't happen
            "this will be replaced".try_into().unwrap(),
            false,
        )
        .unwrap(),
    ];

    let context = ContextBuilder::new("someuser".to_owned()).build();
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
            Argument::new(
                "service".try_into().unwrap(),
                "authorizeme".try_into().unwrap(),
                true
            )
            .unwrap(),
            Argument::new(
                "thing".try_into().unwrap(),
                "not important".try_into().unwrap(),
                false
            )
            .unwrap(),
            // arguments set on server are appended to the provided list (I believe)
            Argument::new("number".try_into().unwrap(), "42".try_into().unwrap(), true).unwrap()
        ]
    );
}

#[async_std::test]
async fn authorize_fail_wrong_argument_value() {
    let address = common::get_server_address();
    let connection_factory: ConnectionFactory<_> =
        Box::new(move || TcpStream::connect(address.clone()).boxed());

    let client = Client::new(connection_factory, Some(common::SECRET_KEY));

    let arguments = vec![
        Argument::new(
            "service".try_into().unwrap(),
            "authorizeme".try_into().unwrap(),
            true,
        )
        .unwrap(),
        // the Shrubbery TACACS+ daemon denies authorization requests where mandatory arguments don't match their configured values
        Argument::new("number".try_into().unwrap(), "3".try_into().unwrap(), true).unwrap(),
    ];

    let context = ContextBuilder::new("someuser".to_owned()).build();
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
    let address = common::get_server_address();
    let factory: ConnectionFactory<TcpStream> =
        Box::new(move || TcpStream::connect(address.clone()).boxed());
    let client = Client::new(factory, Some(common::SECRET_KEY));

    let arguments = vec![Argument::new(
        "service".try_into().unwrap(),
        "guest".try_into().unwrap(),
        true,
    )
    .unwrap()];

    let context = ContextBuilder::new(String::new())
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
            Argument::new(
                "service".try_into().unwrap(),
                "guest".try_into().unwrap(),
                true
            )
            .unwrap(),
            Argument::new(
                "priv-lvl".try_into().unwrap(),
                "0".try_into().unwrap(),
                true
            )
            .unwrap(),
            Argument::new(
                "authenticated".try_into().unwrap(),
                "false".try_into().unwrap(),
                true
            )
            .unwrap()
        ]
    );
}
