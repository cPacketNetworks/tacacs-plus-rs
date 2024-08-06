use async_net::TcpStream;
use futures::FutureExt;

use tacacs_plus::client::ResponseStatus;
use tacacs_plus::client::{ConnectionFactory, ContextBuilder};
use tacacs_plus::Client;
use tacacs_plus_protocol::ArgumentOwned;

#[test]
fn main() {
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
        // NOTE: uncommenting this will cause the authorization to fail, since the argument value won't match the server config
        // ArgumentOwned {
        //     name: "number".to_owned(),
        //     value: "3".to_owned(),
        //     required: true,
        // },
        ArgumentOwned {
            name: "thing".to_owned(),
            // the shrubbery TACACS+ daemon at least replaces optional arguments whose values are different from the server config
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

    assert!(
        response.status == ResponseStatus::Success,
        "authorization failed, full response: {response:?}"
    );

    for argument in response.arguments {
        let required_str = if argument.required {
            "required"
        } else {
            "optional"
        };

        println!("{} = {} ({})", argument.name, argument.value, required_str);
    }
}
