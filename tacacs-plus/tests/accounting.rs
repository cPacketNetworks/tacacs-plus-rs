use std::time::Duration;

use futures::{FutureExt, TryFutureExt};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use tacacs_plus::Argument;
use tacacs_plus::{AccountingResponse, Client, ContextBuilder};

mod common;

#[tokio::test]
async fn account_start_update_stop() {
    let address = common::get_server_address();

    let client = Client::new(
        Box::new(move || {
            TcpStream::connect(address.clone())
                .map_ok(TokioAsyncWriteCompatExt::compat_write)
                .boxed()
        }),
        Some(common::SECRET_KEY),
    );

    let context = ContextBuilder::new("account").build();
    let start_arguments = vec![Argument {
        name: "custom".to_owned(),
        value: "something".to_owned(),
        required: true,
    }];

    // the shrubbery TACACS+ daemon returns empty responses on success
    let empty_response = AccountingResponse {
        user_message: String::new(),
        admin_message: String::new(),
    };

    let (task, start_response) = client
        .account_begin(context, start_arguments)
        .await
        .expect("task creation should have succeeded");
    assert_eq!(start_response, empty_response);

    tokio::time::sleep(Duration::from_secs(1)).await;

    // NOTE: the shrubbery TACACS+ daemon doesn't actually handle this properly; it shows up as a start rather than an update
    // the semantics of accounting packet flags changed between the TACACS+ draft & RFC8907
    let update_args = vec![Argument {
        name: "custom2".to_owned(),
        value: "".to_owned(),
        required: false,
    }];
    let update_response = task
        .update(update_args)
        .await
        .expect("task update should have succeeded");
    assert_eq!(update_response, empty_response);

    tokio::time::sleep(Duration::from_secs(1)).await;

    let stop_response = task
        .stop(Vec::new())
        .await
        .expect("stopping task should have succeeded");
    assert_eq!(stop_response, empty_response);
}
