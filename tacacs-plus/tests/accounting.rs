use std::time::Duration;

use futures::{FutureExt, TryFutureExt};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use tacacs_plus::Argument;
use tacacs_plus::{Client, ContextBuilder};

#[tokio::test]
async fn account_start_update_stop() {
    let client = Client::new(
        Box::new(|| {
            TcpStream::connect("localhost:5555")
                .map_ok(TokioAsyncWriteCompatExt::compat_write)
                .boxed()
        }),
        Some("very secure key that is super secret"),
    );

    let context = ContextBuilder::new("account").build();
    let start_arguments = vec![Argument {
        name: "custom".to_owned(),
        value: "something".to_owned(),
        required: true,
    }];

    let (task, _) = client
        .create_task(context, start_arguments)
        .await
        .expect("task creation should have succeeded");

    tokio::time::sleep(Duration::from_secs(1)).await;

    // NOTE: the shrubbery TACACS+ daemon doesn't actually handle this properly; it shows up as a start rather than an update
    // the semantics of accounting packet flags changed between the TACACS+ draft & RFC8907
    let update_args = vec![Argument {
        name: "custom2".to_owned(),
        value: "".to_owned(),
        required: false,
    }];
    task.update(update_args)
        .await
        .expect("task update should have succeeded");

    tokio::time::sleep(Duration::from_secs(1)).await;

    task.stop(Vec::new())
        .await
        .expect("stopping task should have succeeded");
}
