// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Private HTTP sidecar serving proof material from a node's databases,
//! opened strictly read-only. No auth: bind it to localhost behind an API
//! that authenticates and rate-limits.
//!
//! | Route | Response |
//! |---|---|
//! | `GET /witness/{index_block_hash}` | wire v3 bytes, `x-block-height`, `x-state-root`; 404 unknown; 503 + `retry-after: 1` when every extraction slot is busy |
//! | `GET /burn/{consensus_hash}` | `{consensus_hash, burn_height, bitcoin_block_hash, preimage}`; 404 unknown |
//! | `GET /bitcoin/headers?from=H&count=N` | `{from, headers: [80-byte hex, …]}`, 1 ≤ N ≤ 2016, truncated at the tip |
//! | `GET /health` | `{ok, marf_tip_height, bitcoin_tip_height}` |
//!
//! Threads: the accept loop only hands connections to a bounded queue (a full
//! queue gets an immediate 503). A fixed pool of workers serves them, each
//! with its own lazily opened read-only handles (MARF, sortition DB, headers
//! DB), so no handle is shared across threads. Witness extraction additionally
//! takes one of `max_concurrent_extractions` slots, never waiting for one;
//! extracted witnesses are kept in a byte-bounded LRU keyed by block id.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use serde_json::json;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::hash::to_hex;

use crate::extract::{ReadOnlyMarf, checked_witness};
use crate::{burn, headers};

/// Workers beyond the extraction slots, for cheap requests (cache hits,
/// burn, headers, health, 503s) while every slot is extracting.
const CHEAP_WORKERS: usize = 8;
/// Accepted connections waiting for a worker before new ones get a 503.
const QUEUE: usize = 64;
/// Longest request head (request line + headers) read.
const MAX_HEAD: u64 = 16 * 1024;

pub struct Config {
    pub marf: PathBuf,
    pub sortition_db: PathBuf,
    pub headers_db: PathBuf,
    pub listen: SocketAddr,
    pub max_concurrent_extractions: usize,
    pub cache_bytes: usize,
    pub request_timeout: Duration,
}

/// Non-blocking counting semaphore bounding concurrent witness extractions.
pub struct Slots {
    max: usize,
    used: AtomicUsize,
}

/// A held extraction slot, released on drop.
pub struct Slot(Arc<Slots>);

impl Slots {
    /// Take a slot if one is free; never waits.
    pub fn try_acquire(self: &Arc<Self>) -> Option<Slot> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.max).then_some(n + 1)
            })
            .ok()
            .map(|_| Slot(Arc::clone(self)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::AcqRel);
    }
}

struct CachedWitness {
    bytes: Arc<Vec<u8>>,
    height: u32,
    root_hex: String,
}

/// Least-recently-used witnesses, bounded by total witness bytes.
struct Lru {
    cap: usize,
    used: usize,
    tick: u64,
    map: HashMap<StacksBlockId, (Arc<CachedWitness>, u64)>,
    order: BTreeMap<u64, StacksBlockId>,
}

impl Lru {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            used: 0,
            tick: 0,
            map: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    fn get(&mut self, id: &StacksBlockId) -> Option<Arc<CachedWitness>> {
        self.tick += 1;
        let (w, t) = self.map.get_mut(id)?;
        self.order.remove(t);
        *t = self.tick;
        self.order.insert(self.tick, id.clone());
        Some(Arc::clone(w))
    }

    fn insert(&mut self, id: StacksBlockId, w: Arc<CachedWitness>) {
        let size = w.bytes.len();
        if size > self.cap || self.map.contains_key(&id) {
            return;
        }
        while self.used + size > self.cap {
            let Some((_, old)) = self.order.pop_first() else {
                break;
            };
            if let Some((evicted, _)) = self.map.remove(&old) {
                self.used -= evicted.bytes.len();
            }
        }
        self.tick += 1;
        self.used += size;
        self.order.insert(self.tick, id.clone());
        self.map.insert(id, (w, self.tick));
    }
}

struct Shared {
    cfg: Config,
    slots: Arc<Slots>,
    cache: Mutex<Lru>,
}

pub struct Server {
    listener: TcpListener,
    shared: Arc<Shared>,
}

impl Server {
    /// Check every database opens read-only, then bind `cfg.listen`.
    pub fn bind(cfg: Config) -> Result<Self, String> {
        drop(ReadOnlyMarf::open(&cfg.marf)?);
        drop(burn::open_readonly(&cfg.sortition_db)?);
        drop(headers::open_readonly(&cfg.headers_db)?);
        let listener =
            TcpListener::bind(cfg.listen).map_err(|e| format!("bind {}: {e}", cfg.listen))?;
        Ok(Self {
            listener,
            shared: Arc::new(Shared {
                slots: Arc::new(Slots {
                    max: cfg.max_concurrent_extractions,
                    used: AtomicUsize::new(0),
                }),
                cache: Mutex::new(Lru::new(cfg.cache_bytes)),
                cfg,
            }),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, String> {
        self.listener.local_addr().map_err(|e| e.to_string())
    }

    /// The extraction slots; holding them all makes uncached witnesses 503.
    pub fn extraction_slots(&self) -> Arc<Slots> {
        Arc::clone(&self.shared.slots)
    }

    /// Serve until the listener fails.
    pub fn run(self) -> Result<(), String> {
        let (tx, rx) = sync_channel::<(TcpStream, Instant)>(QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..self.shared.cfg.max_concurrent_extractions + CHEAP_WORKERS {
            let (shared, rx) = (Arc::clone(&self.shared), Arc::clone(&rx));
            std::thread::Builder::new()
                .name(format!("serve-{i}"))
                .spawn(move || worker(&shared, &rx))
                .map_err(|e| format!("spawn worker: {e}"))?;
        }
        for conn in self.listener.incoming() {
            let stream = match conn {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("accept: {e}");
                    continue;
                }
            };
            match tx.try_send((stream, Instant::now())) {
                Ok(()) => {}
                Err(TrySendError::Full((stream, start))) => {
                    // A ~150-byte reply fits a fresh socket's send buffer.
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
                    let r = busy("all workers are busy");
                    finish(stream, "-", "-", r, start);
                }
                Err(TrySendError::Disconnected(_)) => return Err("workers exited".into()),
            }
        }
        Ok(())
    }
}

/// A worker's read-only database handles, opened on first use.
#[derive(Default)]
struct Handles {
    marf: Option<ReadOnlyMarf>,
    sortition: Option<Connection>,
    headers: Option<Connection>,
}

impl Handles {
    fn marf(&mut self, cfg: &Config) -> Result<&mut ReadOnlyMarf, String> {
        if self.marf.is_none() {
            self.marf = Some(ReadOnlyMarf::open(&cfg.marf)?);
        }
        Ok(self.marf.as_mut().expect("opened"))
    }

    fn sortition(&mut self, cfg: &Config) -> Result<&Connection, String> {
        if self.sortition.is_none() {
            self.sortition = Some(burn::open_readonly(&cfg.sortition_db)?);
        }
        Ok(self.sortition.as_ref().expect("opened"))
    }

    fn headers(&mut self, cfg: &Config) -> Result<&Connection, String> {
        if self.headers.is_none() {
            self.headers = Some(headers::open_readonly(&cfg.headers_db)?);
        }
        Ok(self.headers.as_ref().expect("opened"))
    }
}

fn worker(shared: &Shared, rx: &Mutex<Receiver<(TcpStream, Instant)>>) {
    let mut handles = Handles::default();
    loop {
        let next = rx.lock().map(|rx| rx.recv());
        let Ok(Ok((stream, start))) = next else {
            return;
        };
        let timeout = Some(shared.cfg.request_timeout);
        let _ = stream.set_read_timeout(timeout);
        let _ = stream.set_write_timeout(timeout);
        let (method, target) = match read_head(&stream) {
            Ok(head) => head,
            Err(r) => {
                finish(stream, "-", "-", r, start);
                continue;
            }
        };
        let r = if method != "GET" {
            let mut r = error(405, "only GET is served");
            r.headers.push(("allow", "GET".into()));
            r
        } else {
            match catch_unwind(AssertUnwindSafe(|| route(shared, &mut handles, &target))) {
                Ok(r) => r,
                Err(_) => {
                    // The panic may have left a handle mid-operation: reopen.
                    handles = Handles::default();
                    error(500, "internal error")
                }
            }
        };
        finish(stream, &method, &target, r, start);
    }
}

struct Response {
    status: u16,
    content_type: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Arc<Vec<u8>>,
}

fn json_response(status: u16, body: &serde_json::Value) -> Response {
    Response {
        status,
        content_type: "application/json",
        headers: vec![],
        body: Arc::new(body.to_string().into_bytes()),
    }
}

fn error(status: u16, msg: &str) -> Response {
    json_response(status, &json!({ "error": msg }))
}

fn busy(msg: &str) -> Response {
    let mut r = error(503, msg);
    r.headers.push(("retry-after", "1".into()));
    r
}

/// Request line and headers. Only the method and target are used.
fn read_head(stream: &TcpStream) -> Result<(String, String), Response> {
    let mut reader = BufReader::new(stream.take(MAX_HEAD));
    let mut line = String::new();
    let bad = |_| error(400, "malformed request");
    reader.read_line(&mut line).map_err(bad)?;
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(error(400, "malformed request line"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(error(400, "HTTP/1.x only"));
    }
    let head = (method.to_string(), target.to_string());
    loop {
        line.clear();
        match reader.read_line(&mut line).map_err(bad)? {
            0 => return Err(error(400, "request head too long or truncated")),
            _ if line == "\r\n" || line == "\n" => return Ok(head),
            _ => {}
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// Write `r`, close the connection and log one line.
fn finish(mut stream: TcpStream, method: &str, target: &str, r: Response, start: Instant) {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len()
    );
    for (k, v) in &r.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let sent = stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(&r.body))
        .and_then(|_| stream.flush());
    let target: String = target.chars().take(200).collect();
    let note = sent
        .err()
        .map(|e| format!(" write_error={e}"))
        .unwrap_or_default();
    eprintln!(
        "method={method} path={target} status={} bytes={} ms={}{note}",
        r.status,
        r.body.len(),
        start.elapsed().as_millis()
    );
}

fn route(shared: &Shared, handles: &mut Handles, target: &str) -> Response {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    let r = match segments.as_slice() {
        ["witness", id] => witness(shared, handles, id),
        ["burn", ch] => burn_route(shared, handles, ch),
        ["bitcoin", "headers"] => headers_route(shared, handles, query),
        ["health"] => health(shared, handles),
        _ => Ok(error(404, "no such route")),
    };
    r.unwrap_or_else(|e| {
        eprintln!("error: {target}: {e}");
        error(500, &e)
    })
}

fn witness_response(w: &CachedWitness, cache: &'static str) -> Response {
    Response {
        status: 200,
        content_type: "application/octet-stream",
        headers: vec![
            ("x-block-height", w.height.to_string()),
            ("x-state-root", w.root_hex.clone()),
            (
                "cache-control",
                "public, max-age=31536000, immutable".into(),
            ),
            ("x-cache", cache.into()),
        ],
        body: Arc::clone(&w.bytes),
    }
}

fn witness(shared: &Shared, handles: &mut Handles, id: &str) -> Result<Response, String> {
    let Ok(id) = StacksBlockId::from_hex(id.trim_start_matches("0x")) else {
        return Ok(error(400, "not a 32-byte hex index block hash"));
    };
    let cached = || -> Result<Option<Arc<CachedWitness>>, String> {
        Ok(shared.cache.lock().map_err(|e| e.to_string())?.get(&id))
    };
    if let Some(w) = cached()? {
        return Ok(witness_response(&w, "hit"));
    }
    let Some(_slot) = shared.slots.try_acquire() else {
        return Ok(busy("all extraction slots are busy"));
    };
    // Another request may have extracted it while this one waited for a worker.
    if let Some(w) = cached()? {
        return Ok(witness_response(&w, "hit"));
    }
    let Some((bytes, meta)) = checked_witness(handles.marf(&shared.cfg)?, &id)? else {
        return Ok(error(404, "block is not in the MARF"));
    };
    let w = Arc::new(CachedWitness {
        bytes: Arc::new(bytes),
        height: meta.height,
        root_hex: meta.root_hex,
    });
    shared
        .cache
        .lock()
        .map_err(|e| e.to_string())?
        .insert(id, Arc::clone(&w));
    Ok(witness_response(&w, "miss"))
}

fn burn_route(shared: &Shared, handles: &mut Handles, ch: &str) -> Result<Response, String> {
    let ch = ch.trim_start_matches("0x");
    if ch.len() != 40 || !ch.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(error(400, "not a 20-byte hex consensus hash"));
    }
    let conn = handles.sortition(&shared.cfg)?;
    Ok(
        match burn::burn_preimage(conn, ch, burn::MAINNET_FIRST_BURN_HEIGHT)? {
            Some(p) => json_response(200, &json!(p)),
            None => error(404, "no snapshot with this consensus hash"),
        },
    )
}

fn headers_route(shared: &Shared, handles: &mut Handles, query: &str) -> Result<Response, String> {
    let param = |name: &str| {
        query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == name)
            .and_then(|(_, v)| v.parse::<u64>().ok())
    };
    let (Some(from), Some(count)) = (param("from"), param("count")) else {
        return Ok(error(400, "from and count must be non-negative integers"));
    };
    if !(1..=headers::MAX_HEADERS).contains(&count) {
        return Ok(error(400, "count must be between 1 and 2016"));
    }
    let hs = headers::read_headers(handles.headers(&shared.cfg)?, from, count)?;
    let hex: Vec<String> = hs.iter().map(|h| to_hex(h)).collect();
    Ok(json_response(200, &json!({ "from": from, "headers": hex })))
}

fn health(shared: &Shared, handles: &mut Handles) -> Result<Response, String> {
    let marf_tip = handles.marf(&shared.cfg).and_then(|m| {
        let latest = m.latest_block()?;
        m.height_of(&latest)
    });
    let btc_tip = handles
        .headers(&shared.cfg)
        .and_then(headers::tip_height)
        .and_then(|h| h.ok_or_else(|| "headers DB is empty".to_string()));
    let errors: Vec<&str> = [marf_tip.as_ref().err(), btc_tip.as_ref().err()]
        .into_iter()
        .flatten()
        .map(String::as_str)
        .collect();
    let mut body = json!({
        "ok": errors.is_empty(),
        "marf_tip_height": marf_tip.as_ref().ok(),
        "bitcoin_tip_height": btc_tip.as_ref().ok(),
    });
    if !errors.is_empty() {
        body["error"] = json!(errors.join("; "));
    }
    Ok(json_response(
        if errors.is_empty() { 200 } else { 503 },
        &body,
    ))
}
