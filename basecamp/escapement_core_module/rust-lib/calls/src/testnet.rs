//! A stand-in LEZ v0.4 sequencer for the tests: JSON-RPC over HTTP on 127.0.0.1, only the methods the module calls,
//! the actor states, balances and nonces a test puts in, and a record of every transaction sent to it.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

#[derive(Default)]
pub struct Chain {
    /// (account id, program id), base58 -> the actor state's bytes.
    pub states: HashMap<(String, String), Vec<u8>>,
    pub balances: HashMap<String, u128>,
    pub nonces: HashMap<String, u128>,
    /// The hashes of the transactions sent (`sendTransaction`), in order.
    pub sent: Vec<String>,
    /// Record a sent transaction but answer HTTP 500 (an answer lost after the sequencer took it).
    pub lose_send_answer: bool,
    /// Actor states removed once a transaction is sent (a read-back that finds nothing).
    pub drop_on_send: Vec<(String, String)>,
    /// Answer `sendTransaction` with this JSON-RPC error (the sequencer refusing; nothing recorded as sent).
    pub refuse_send: Option<String>,
    /// Once a transaction is sent, answer every `getAccount` with HTTP 500 (the read-back cannot be made).
    pub fail_reads_after_send: bool,
}

pub struct Testnet {
    pub url: String,
    pub chain: Arc<Mutex<Chain>>,
}

impl Testnet {
    pub fn start() -> Self {
        let l = TcpListener::bind("127.0.0.1:0").expect("a port on 127.0.0.1");
        let url = format!("http://127.0.0.1:{}", l.local_addr().expect("the port").port());
        let chain = Arc::new(Mutex::new(Chain::default()));
        let c = chain.clone();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut s) = stream else { continue };
                let c = c.clone();
                std::thread::spawn(move || {
                    let _ = serve(&mut s, &c);
                });
            }
        });
        Testnet { url, chain }
    }

    pub fn sent(&self) -> usize {
        self.chain.lock().unwrap().sent.len()
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn serve(s: &mut TcpStream, c: &Mutex<Chain>) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let end = loop {
        let n = s.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    let len = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok()).flatten()
        })
        .unwrap_or(0);
    while buf.len() < end + len {
        let n = s.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body: Value = serde_json::from_slice(&buf[end..(end + len).min(buf.len())]).unwrap_or(Value::Null);
    match answer(&body, c) {
        Ok(result) => {
            let out = json!({ "jsonrpc": "2.0", "id": body["id"].clone(), "result": result }).to_string();
            write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len())?;
        }
        Err(0) => {
            let msg = c.lock().unwrap().refuse_send.clone().unwrap_or_default();
            let out = json!({ "jsonrpc": "2.0", "id": body["id"].clone(), "error": { "code": -32000, "message": msg } }).to_string();
            write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len())?;
        }
        Err(status) => write!(s, "HTTP/1.1 {status} Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?,
    }
    s.flush()
}

fn answer(req: &Value, c: &Mutex<Chain>) -> Result<Value, u16> {
    let mut ch = c.lock().unwrap();
    let p = &req["params"];
    let arg = |i: usize| p[i].as_str().unwrap_or("").to_string();
    Ok(match req["method"].as_str().unwrap_or("") {
        "getLastBlockId" => json!(7),
        "getFeeState" => json!({ "base_fee_exec": 8, "base_fee_stor": 8 }),
        "getAccountBalance" => json!(ch.balances.get(&arg(0)).copied().unwrap_or(0).to_string()),
        "getAccountsNonces" => json!(p[0]
            .as_array()
            .map(|a| a.iter().map(|id| ch.nonces.get(id.as_str().unwrap_or("")).copied().unwrap_or(0) as u64).collect::<Vec<_>>())
            .unwrap_or_default()),
        "getAccount" => {
            if ch.fail_reads_after_send && !ch.sent.is_empty() {
                return Err(500);
            }
            let id = arg(0);
            let states: serde_json::Map<String, Value> =
                ch.states.iter().filter(|((a, _), _)| *a == id).map(|((_, prog), b)| (prog.clone(), json!(b))).collect();
            if states.is_empty() {
                Value::Null
            } else {
                json!({ "nonce": 0, "data": { "actor_states": states } })
            }
        }
        "sendTransaction" => {
            if ch.refuse_send.is_some() {
                return Err(0);
            }
            use base64::Engine as _;
            let raw = base64::engine::general_purpose::STANDARD.decode(arg(0)).unwrap_or_default();
            let hash = hex::encode(crate::lez::sha256(&[raw.get(1..).unwrap_or(&[])]));
            ch.sent.push(hash.clone());
            let drop = std::mem::take(&mut ch.drop_on_send);
            for k in drop {
                ch.states.remove(&k);
            }
            if ch.lose_send_answer {
                return Err(500);
            }
            json!(hash)
        }
        "getTransaction" => {
            let h = arg(0);
            if ch.sent.contains(&h) {
                json!([Value::Null, 8])
            } else {
                Value::Null
            }
        }
        _ => Value::Null,
    })
}
