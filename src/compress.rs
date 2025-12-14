use brotli::CompressorWriter;
use http::{HeaderMap, Uri, header};
use http_body_util::{BodyExt as _, combinators::BoxBody};
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use std::{
    collections::BTreeSet,
    io::Write,
    mem,
    pin::Pin,
    task::{Context, Poll},
};
use tracing::debug;

use crate::StdError;

const NO_COMPRESS_MIME_CLASS: &[&str] = &["image", "video", "audio"];
const NO_COMPRESS_MIME: &[&str] = &[
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
];
const ALWAYS_COMPRESS_MIME: &[&str] = &["image/svg+xml", "image/svg"];

const BUFFER_SIZE: usize = 100 * 1024;

pub fn process_body(
    accept_encodings: &BTreeSet<String>,
    uri: &Uri,
    headers: &mut HeaderMap,
    body: Incoming,
) -> BoxBody<Bytes, StdError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap()
        .trim()
        .to_lowercase();
    if !accept_encodings.contains("br")
        || headers.contains_key(header::CONTENT_ENCODING)
        || (!ALWAYS_COMPRESS_MIME.contains(&content_type.as_str())
            && (NO_COMPRESS_MIME.contains(&content_type.as_str())
                || NO_COMPRESS_MIME_CLASS.contains(
                    &content_type
                        .split('/')
                        .next()
                        .unwrap_or("")
                        .to_lowercase()
                        .as_str(),
                )))
    {
        return body.map_err(|e| Box::new(e) as StdError).boxed();
    }
    debug!(
        uri = uri.path(),
        content_type = content_type,
        "Applying brotli compression",
    );
    brotli_body(headers, body)
}

struct BrotliEncoder {
    inner: CompressorWriter<Vec<u8>>,
}

impl BrotliEncoder {
    fn new() -> Self {
        Self {
            inner: CompressorWriter::new(
                Vec::new(),
                4096, // internal buffer
                5,    // quality (tune as needed)
                22,   // lgwin
            ),
        }
    }

    fn write(&mut self, data: &[u8]) -> Bytes {
        self.inner.write_all(data).unwrap();
        let out = std::mem::take(self.inner.get_mut());
        Bytes::from(out)
    }

    fn finish(mut self) -> Bytes {
        self.inner.flush().unwrap();
        Bytes::from(self.inner.into_inner())
    }
}

struct BrotliStream<B> {
    stream: B,
    encoder: Option<BrotliEncoder>,
    buffer: Vec<u8>,
    finished: bool,
}

impl<B> BrotliStream<B> {
    fn new(stream: B) -> Self {
        Self {
            stream,
            encoder: Some(BrotliEncoder::new()),
            buffer: Vec::with_capacity(BUFFER_SIZE),
            finished: false,
        }
    }
}

impl<B> Body for BrotliStream<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<StdError>,
{
    type Data = Bytes;
    type Error = StdError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }

        loop {
            match Pin::new(&mut self.stream).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        self.buffer.extend_from_slice(data);

                        if self.buffer.len() >= BUFFER_SIZE {
                            let buf = mem::take(&mut self.buffer);
                            let out = self.encoder.as_mut().unwrap().write(&buf);
                            return Poll::Ready(Some(Ok(Frame::data(out))));
                        }
                    }
                }

                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(e.into())));
                }

                Poll::Ready(None) => {
                    let mut out = Vec::new();

                    if !self.buffer.is_empty() {
                        let buf = mem::take(&mut self.buffer);
                        out.extend_from_slice(&self.encoder.as_mut().unwrap().write(&buf));
                        self.buffer.clear();
                    }

                    out.extend_from_slice(&self.encoder.take().unwrap().finish());
                    self.finished = true;

                    if out.is_empty() {
                        return Poll::Ready(None);
                    }

                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                }

                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
}

pub fn brotli_body(headers: &mut HeaderMap, body: Incoming) -> BoxBody<Bytes, StdError> {
    let brotli_stream = BrotliStream::new(body);

    headers.remove(header::CONTENT_LENGTH);
    headers.insert(header::CONTENT_ENCODING, "br".parse().unwrap());

    BoxBody::new(brotli_stream)
}
