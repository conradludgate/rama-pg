use std::{net::SocketAddr, sync::Arc, time::Duration};

use rama_pg::{
    pool::{BackendPool, Lease, PoolMode},
    protocol::{codec, message, startup},
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::oneshot,
    task::{JoinHandle, JoinSet},
};

struct Backend {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Backend {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let mut next = 0;
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let (mut stream, _) = incoming.unwrap();
                        next += 1;
                        let id = next;
                        connections.spawn(async move {
                            startup::read_startup_frame(&mut stream).await.unwrap();
                            stream.write_all(&message::authentication_ok()).await.unwrap();
                            stream.write_all(&message::parameter_status("test_connection", &id.to_string())).await.unwrap();
                            stream.write_all(&message::ready_for_query(b'I')).await.unwrap();
                            while let Ok(query) = codec::read_message(&mut stream).await {
                                assert_eq!(query.tag(), codec::QUERY);
                                if stream.write_all(&message::ready_for_query(b'I')).await.is_err() { break; }
                            }
                        });
                    }
                    done = connections.join_next(), if !connections.is_empty() => { done.unwrap().unwrap(); }
                }
            }
        });
        Self { address, task }
    }

    fn pool(&self) -> Arc<BackendPool> {
        BackendPool::new(vec![self.address.to_string()], 1, PoolMode::Transaction)
    }
}

fn startup() -> Vec<u8> {
    startup::startup_message(&[("user", "alice"), ("database", "app")]).to_vec()
}

#[tokio::test]
async fn implicit_drop_does_not_repool_a_used_stream() {
    tokio::time::timeout(Duration::from_secs(10), async {
        eprintln!("Lease size: {} bytes", std::mem::size_of::<Lease>());
        let backend = Backend::start().await;
        let pool = backend.pool();
        let mut first = pool.lease(&startup(), "alice", "app").await.unwrap();
        let identity = first.params();
        first
            .write_all(&codec::frame(codec::QUERY, b"select 1\0"))
            .await
            .unwrap();
        first.flush().await.unwrap();
        drop(first); // The query's response has not been consumed.
        let second = pool.lease(&startup(), "alice", "app").await.unwrap();
        assert_ne!(
            second.params(),
            identity,
            "implicitly dropped lease was reused"
        );
        second.discard();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn aborting_a_task_discards_its_backend() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let backend = Backend::start().await;
        let pool = backend.pool();
        let mut first = pool.lease(&startup(), "alice", "app").await.unwrap();
        let identity = first.params();
        let (ready, entered) = oneshot::channel();
        let work = tokio::spawn(async move {
            first
                .write_all(&codec::frame(codec::QUERY, b"select 1\0"))
                .await
                .unwrap();
            first.flush().await.unwrap();
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
            first.checkin();
        });
        entered.await.unwrap();
        work.abort();
        assert!(work.await.unwrap_err().is_cancelled());
        let second = pool.lease(&startup(), "alice", "app").await.unwrap();
        assert_ne!(
            second.params(),
            identity,
            "aborted query backend was reused"
        );
        second.discard();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn explicit_checkin_reuses_a_pristine_backend() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let backend = Backend::start().await;
        let pool = backend.pool();
        let first = pool.lease(&startup(), "alice", "app").await.unwrap();
        let identity = first.params();
        first.checkin();
        let second = pool.lease(&startup(), "alice", "app").await.unwrap();
        assert_eq!(second.params(), identity);
        second.discard();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn explicit_discard_releases_capacity_for_a_new_connection() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let backend = Backend::start().await;
        let pool = backend.pool();
        let first = pool.lease(&startup(), "alice", "app").await.unwrap();
        let identity = first.params();
        first.discard();
        let second = pool.lease(&startup(), "alice", "app").await.unwrap();
        assert_ne!(second.params(), identity);
        second.discard();
    })
    .await
    .unwrap();
}
