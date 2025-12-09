use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Arc,
};

use bma_ts::Timestamp;
use http::HeaderName;
use hyper::body::Incoming;
use hyper::{HeaderMap, Request};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RequestMeta {
    pub ts: u64,
    pub method: String,
    pub path_len: usize,
    pub query_len: usize,
    pub num_headers: usize,
    pub has_user_agent: bool,
    pub ua_len: usize,
    pub body_size: usize,
    pub ip_hash: u64,
    pub header_shape_hash: u64,

    pub requests_last_window: usize,
    pub unique_paths_last_window: usize,
    pub mean_body_size_last_window: f64,

    pub r: String,
}

#[derive(Debug, Clone)]
struct IpWindowEntry {
    ts: u64,
    path_hash: u64,
    body_size: usize,
}

#[derive(Debug)]
struct IpState {
    deque: VecDeque<IpWindowEntry>,
    unique_paths: HashSet<u64>,
    sum_body_size: usize,
}

impl IpState {
    fn new() -> Self {
        Self {
            deque: VecDeque::new(),
            unique_paths: HashSet::new(),
            sum_body_size: 0,
        }
    }

    fn push_event(&mut self, entry: IpWindowEntry, window: u64) {
        let now = entry.ts;
        self.deque.push_back(entry);
        self.evict_old(now, window);
        self.recompute();
    }

    fn evict_old(&mut self, now: u64, window: u64) {
        while let Some(front) = self.deque.front() {
            if now.saturating_sub(front.ts) > window {
                self.deque.pop_front();
            } else {
                break;
            }
        }
    }

    fn recompute(&mut self) {
        self.unique_paths.clear();
        self.sum_body_size = 0;

        for e in &self.deque {
            self.unique_paths.insert(e.path_hash);
            self.sum_body_size += e.body_size;
        }
    }

    fn requests(&self) -> usize {
        self.deque.len()
    }

    fn unique_paths(&self) -> usize {
        self.unique_paths.len()
    }

    #[allow(clippy::cast_precision_loss)]
    fn mean_body_size(&self) -> f64 {
        if self.deque.is_empty() {
            0.0
        } else {
            self.sum_body_size as f64 / self.deque.len() as f64
        }
    }
}

#[derive(Clone)]
pub struct RequestFeatureExtractor {
    inner: Arc<Mutex<HashMap<u64, IpState>>>,
    window_secs: u64,
}

impl RequestFeatureExtractor {
    /// Create extractor with 30-second window
    pub fn new(window_secs: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            window_secs,
        }
    }

    /// MAIN ENTRY POINT:
    /// Build RequestMeta directly from hyper::Request<Incoming>
    pub fn extract(&self, req: &Request<Incoming>, remote_ip: IpAddr) -> RequestMeta {
        let ts = Timestamp::now().as_secs();

        // ---- Static features (no body read) ----
        let uri = req.uri();
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string)
            .unwrap_or_default();

        let full_path = format!("{}{}", host, uri.path());
        let query = uri.query().unwrap_or("");
        let headers = req.headers();

        let method = req.method().as_str().to_owned();
        let path_len = full_path.len();
        let query_len = query.len();
        let num_headers = headers.len();

        let (has_user_agent, ua_len) = match headers.get(hyper::header::USER_AGENT) {
            Some(v) => (true, v.as_bytes().len()),
            None => (false, 0),
        };

        let body_size = headers
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        let ip_hash = hash_ip(&remote_ip);
        let header_shape_hash = header_shape_hash(headers);

        let path_hash = simple_hash_str(&full_path);

        let (requests, unique_paths, mean_body) = {
            let mut map = self.inner.lock();
            let st = map.entry(ip_hash).or_insert_with(IpState::new);
            st.push_event(
                IpWindowEntry {
                    ts,
                    path_hash,
                    body_size,
                },
                self.window_secs,
            );
            (st.requests(), st.unique_paths(), st.mean_body_size())
        };

        let r = format!(
            "{} - - [{}] \"{} {}\" {} {} \"{}\" \"{}\"",
            remote_ip,
            ts,
            method,
            uri,
            "-", // status unknown at this point
            body_size,
            headers
                .get(hyper::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-"),
            headers
                .get(hyper::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-"),
        );

        RequestMeta {
            ts,
            method,
            path_len,
            query_len,
            num_headers,
            has_user_agent,
            ua_len,
            body_size,
            ip_hash,
            header_shape_hash,
            requests_last_window: requests,
            unique_paths_last_window: unique_paths,
            mean_body_size_last_window: mean_body,
            r,
        }
    }
}

fn hash_ip(ip: &IpAddr) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut h = DefaultHasher::new();
    ip.hash(&mut h);
    h.finish()
}

fn header_shape_hash(headers: &HeaderMap) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut names: Vec<&str> = headers.keys().map(HeaderName::as_str).collect();
    names.sort_unstable();

    let mut h = DefaultHasher::new();
    names.hash(&mut h);
    h.finish()
}

fn simple_hash_str(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}
