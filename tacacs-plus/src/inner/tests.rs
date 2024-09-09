use std::sync::Arc;
use std::time::Duration;

use futures::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_util::compat::TokioAsyncReadCompatExt;

use super::is_connection_open;

async fn bind_to_port(port: u16) -> TcpListener {
    TcpListener::bind(("localhost", port))
        .await
        .unwrap_or_else(|err| panic!("failed to bind to address localhost:{port}: {err:?}"))
}

#[tokio::test]
async fn connection_open_check() {
    let notify = Arc::new(Notify::new());
    let listener_notify = notify.clone();

    tokio::spawn(async move {
        let listener = bind_to_port(9999).await;
        listener_notify.notify_one();

        let (_stream, _) = listener
            .accept()
            .await
            .expect("failed to accept connection");

        // this is done to keep the stream open for the rest of the test
        listener_notify.notified().await;
    });

    // wait for server to bind to address
    notify.notified().await;

    let client = TcpStream::connect(("localhost", 9999))
        .await
        .expect("couldn't connect to test listener");
    let mut client = client.compat();

    let is_open = is_connection_open(&mut client)
        .await
        .expect("couldn't check if connection was open");
    assert!(is_open);

    notify.notify_one();
}

#[tokio::test]
async fn connection_closed_check() {
    let notify = Arc::new(Notify::new());
    let listener_notify = notify.clone();

    tokio::spawn(async move {
        let listener = bind_to_port(9998).await;
        listener_notify.notify_one();

        let (stream, _) = listener
            .accept()
            .await
            .expect("failed to accept connection");

        let mut stream = stream.compat();

        // close connection & notify main test task
        stream.close().await.unwrap();

        // wait for a bit before notifying main task; this caused some sporadic failures
        // during testing when omitted
        tokio::time::sleep(Duration::from_millis(250)).await;

        // notify main task that stream is closed
        listener_notify.notify_one();
    });

    // wait for server to bind to address
    notify.notified().await;

    let client = TcpStream::connect(("localhost", 9998))
        .await
        .expect("couldn't connect to test listener");
    let mut client = client.compat();

    // let server close connection
    notify.notified().await;

    // ensure connection is detected as closed
    let is_open = is_connection_open(&mut client)
        .await
        .expect("couldn't check if connection was open");
    assert!(!is_open);
}
