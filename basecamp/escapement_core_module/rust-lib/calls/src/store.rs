//! What the module keeps between calls and runs: the network it talks to and the schedule ids it knows per network
//! (`state.json`), and the keys it made itself (`keys/<account>.key`, mode 0600). In `$ESCAPEMENT_MODULE_HOME`, else
//! `$XDG_DATA_HOME/escapement-module`, else `~/.local/share/escapement-module`. Imported keys are not copied: only the
//! path is shown, and the key stays in memory for the session.

use std::io::Write as _;
use std::path::PathBuf;

use serde_json::{json, Value};

/// The network: the sequencer's address and the program. The native asset's units are the module's constants
/// (`NATIVE_DECIMALS`, `NATIVE_LABEL`), not configuration (review R1 M1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub rpc_url: String,
    pub program: String,
    pub read_only: bool,
}

fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("ESCAPEMENT_MODULE_HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(h);
    }
    if let Some(x) = std::env::var_os("XDG_DATA_HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(x).join("escapement-module");
    }
    let h = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    h.join(".local/share/escapement-module")
}

/// Where the state is kept (tests write it as another process would).
pub fn state_path() -> PathBuf {
    home().join("state.json")
}

fn load() -> Value {
    std::fs::read_to_string(state_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_else(|| json!({}))
}

fn save(v: &Value) -> Result<(), String> {
    let d = home();
    std::fs::create_dir_all(&d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
    let tmp = d.join("state.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(v).unwrap_or_default()).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, d.join("state.json")).map_err(|e| format!("cannot write the module's state: {e}"))
}

pub fn config() -> Option<Config> {
    let v = load();
    let c = v.get("config")?;
    Some(Config {
        rpc_url: c.get("rpc_url")?.as_str()?.to_string(),
        program: c.get("program")?.as_str()?.to_string(),
        read_only: c.get("read_only").and_then(Value::as_bool).unwrap_or(false),
    })
}

pub fn set_config(c: &Config) -> Result<(), String> {
    let mut v = load();
    v["config"] = json!({"rpc_url": c.rpc_url, "program": c.program, "read_only": c.read_only});
    save(&v)
}

fn net_key(rpc: &str, program: &str) -> String {
    format!("{rpc} {program}")
}

pub fn tracked(rpc: &str, program: &str) -> Vec<String> {
    load()["schedules"][net_key(rpc, program)]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

pub fn track(rpc: &str, program: &str, schedule: &str) -> Result<(), String> {
    let mut v = load();
    let k = net_key(rpc, program);
    if !v["schedules"].is_object() {
        v["schedules"] = json!({});
    }
    let list = v["schedules"][&k].as_array().cloned().unwrap_or_default();
    if list.iter().any(|x| x.as_str() == Some(schedule)) {
        return Ok(());
    }
    let mut list = list;
    list.push(json!(schedule));
    v["schedules"][&k] = Value::Array(list);
    save(&v)
}

/// Signed transactions not yet seen in a block (their hash, network, kind and summary; never a key).
pub fn unsettled() -> Vec<Value> {
    load()["unsettled"].as_array().cloned().unwrap_or_default()
}

/// Records one before it is sent (the state file is replaced atomically).
pub fn add_unsettled(record: Value) -> Result<(), String> {
    let mut v = load();
    let mut list = v["unsettled"].as_array().cloned().unwrap_or_default();
    list.push(record);
    v["unsettled"] = Value::Array(list);
    save(&v)
}

/// Drops the record of `hash` (seen in a block, or dismissed).
pub fn settle(hash: &str) -> Result<(), String> {
    let mut v = load();
    let list: Vec<Value> =
        v["unsettled"].as_array().cloned().unwrap_or_default().into_iter().filter(|x| x["tx_hash"].as_str() != Some(hash)).collect();
    v["unsettled"] = Value::Array(list);
    save(&v)
}

/// Writes a key the module made, readable only by its owner; the path is returned, the key is not.
pub fn write_key(account: &str, hex_key: &str) -> Result<String, String> {
    let d = home().join("keys");
    std::fs::create_dir_all(&d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
    }
    let p = d.join(format!("{account}.key"));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o.open(&p).map_err(|e| format!("cannot write {}: {e}", p.display()))?;
    f.write_all(hex_key.as_bytes()).map_err(|e| format!("cannot write {}: {e}", p.display()))?;
    Ok(p.display().to_string())
}

/// What `basecamp/scripts/stage.py` staged beside the crate (the commit, each crate's sources' SHA-256).
pub fn staged() -> Value {
    serde_json::from_str(include_str!("../../staged/STAGED.json")).unwrap_or(Value::Null)
}

#[cfg(test)]
pub fn test_home() -> std::sync::MutexGuard<'static, ()> {
    static L: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    let d = std::env::temp_dir().join(format!("escapement-module-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::env::set_var("ESCAPEMENT_MODULE_HOME", &d);
    g
}
