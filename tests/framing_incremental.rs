use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use rama_pg::protocol::codec::read_message_capped;
use tokio::io::{AsyncRead, ReadBuf};

struct HeaderOnly {
    offset: usize,
    largest_body_request: Arc<AtomicUsize>,
}

impl AsyncRead for HeaderOnly {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // A legal 1 MiB claim with no body bytes arriving.
        let header = [b'Q', 0, 16, 0, 0];
        if self.offset == header.len() {
            self.largest_body_request
                .fetch_max(buf.remaining(), Ordering::Relaxed);
            return Poll::Pending;
        }
        let count = (header.len() - self.offset).min(buf.remaining());
        buf.put_slice(&header[self.offset..self.offset + count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn declared_length_does_not_size_the_initial_body_allocation() {
    let largest = Arc::new(AtomicUsize::new(0));
    let mut stream = HeaderOnly {
        offset: 0,
        largest_body_request: largest.clone(),
    };
    let mut read = std::pin::pin!(read_message_capped(&mut stream, 1 << 20));
    let result = std::future::poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx))).await;
    assert!(result.is_pending());
    let requested = largest.load(Ordering::Relaxed);
    assert!(
        requested > 0 && requested <= 128,
        "initial body read requested {requested} bytes"
    );
}
