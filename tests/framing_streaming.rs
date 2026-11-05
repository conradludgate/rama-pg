use std::io;
use std::task::Poll;

use rama_pg::protocol::codec::{self, FramedReader, frame, read_header};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn stream_body_without_consuming_the_next_frame() {
    let body = vec![42; 32 * 1024];
    let first = frame(b'd', &body);
    let next = frame(codec::READY_FOR_QUERY, b"I");
    let wire = [first.as_ref(), next.as_ref()].concat();
    let mut input = wire.as_slice();
    let header = read_header(&mut input, 64 * 1024).await.unwrap();
    assert_eq!(header.tag(), b'd');
    assert_eq!(header.body_len(), body.len());
    assert_eq!(header.as_bytes(), &first[..5]);

    let mut output = Vec::new();
    output.write_all(header.as_bytes()).await.unwrap();
    header
        .copy_body_to(&mut input, &mut output, &mut [0; 127])
        .await
        .unwrap();
    assert_eq!(output, first);
    assert_eq!(input, next);
}

#[tokio::test]
async fn reject_a_header_before_consuming_body_bytes() {
    let message = frame(codec::QUERY, b"too large\0");
    let mut input = &message[..];
    let error = read_header(&mut input, 4).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(input, &message[5..]);

    let mut reader = FramedReader::with_max_len(&message[..], 4);
    let error = reader.read_frame().await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(*reader.get_mut(), &message[5..]);
}

#[tokio::test]
async fn buffered_reader_leaves_following_frames_in_the_transport() {
    let first = frame(codec::READY_FOR_QUERY, b"I");
    // PostgreSQL may send asynchronous notices after ReadyForQuery. A reader
    // handed off at that boundary must not silently discard prefetched bytes.
    let notice = frame(b'N', b"SNOTICE\0Mnotice\0\0");
    let wire = [first.as_ref(), notice.as_ref()].concat();
    let mut reader = FramedReader::new(wire.as_slice());
    assert_eq!(
        reader.read_frame().await.unwrap().unwrap().as_bytes(),
        first
    );
    assert_eq!(*reader.get_mut(), notice);
}

#[tokio::test]
async fn cancellation_preserves_partial_headers_and_bodies() {
    let message = frame(codec::QUERY, b"select 1\0");
    for split in [2, 7] {
        let (mut writer, stream) = tokio::io::duplex(128);
        let mut reader = FramedReader::with_max_len(stream, 128);
        writer.write_all(&message[..split]).await.unwrap();
        {
            let mut read = std::pin::pin!(reader.read_frame());
            let result = std::future::poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx))).await;
            assert!(result.is_pending());
        }
        writer.write_all(&message[split..]).await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(
            reader.read_frame().await.unwrap().unwrap().as_bytes(),
            message
        );
        assert!(reader.read_frame().await.unwrap().is_none());
    }
}

#[tokio::test]
async fn empty_body_needs_no_copy_buffer() {
    let message = frame(codec::TERMINATE, b"");
    let mut input = &message[..];
    let header = read_header(&mut input, 4).await.unwrap();
    header
        .copy_body_to(&mut input, &mut tokio::io::sink(), &mut [])
        .await
        .unwrap();
    assert!(input.is_empty());
}

#[tokio::test]
async fn nonempty_body_rejects_an_empty_copy_buffer() {
    let message = frame(codec::READY_FOR_QUERY, b"I");
    let mut input = &message[..];
    let header = read_header(&mut input, 5).await.unwrap();
    let error = header
        .copy_body_to(&mut input, &mut tokio::io::sink(), &mut [])
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(input, b"I");
}

#[tokio::test]
async fn body_copy_and_buffered_reads_report_truncation() {
    let message = frame(codec::QUERY, b"abcdef");
    for end in [2, 7] {
        let mut reader = FramedReader::new(&message[..end]);
        assert_eq!(
            reader.read_frame().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    let mut input = &message[..message.len() - 1];
    let header = read_header(&mut input, 128).await.unwrap();
    assert_eq!(
        header
            .copy_body_to(&mut input, &mut tokio::io::sink(), &mut [0; 2])
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn one_off_buffered_read_does_not_consume_the_next_frame() {
    let first = frame(codec::QUERY, b"select 1\0");
    let second = frame(codec::TERMINATE, b"");
    let wire = [first.as_ref(), second.as_ref()].concat();
    let mut input = wire.as_slice();
    assert_eq!(
        codec::read_message(&mut input).await.unwrap().as_bytes(),
        first
    );
    let mut rest = Vec::new();
    input.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, second);
}
