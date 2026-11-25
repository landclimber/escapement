//! escapement_core_module's methods run natively through `call`, as the module runs them; the caller is $CALLER
//! (default "host", as logosctl).
//!   call METHOD [REQUEST_JSON | @FILE]     one call; prints the reply
//!   call --script FILE                     one session (the key and the pending transaction stay between lines):
//!                                          each line `[@CALLER ]METHOD REQUEST_JSON`; `$PENDING`, `$TX` and `$SCHEDULE`
//!                                          are the last reply's pending_id, tx_hash and outcome.schedule;
//!                                          `sleep MS` waits; prints `CALLER<TAB>METHOD<TAB>reply`
fn run(method: &str, req: &str, caller: &str) -> String {
    if method == "sleep" {
        std::thread::sleep(std::time::Duration::from_millis(req.trim().parse().unwrap_or(1000)));
        return "{\"ok\":true}".into();
    }
    escapement_module_calls::call(method, req, caller)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let caller = std::env::var("CALLER").unwrap_or_else(|_| "host".into());
    if a.get(1).map(String::as_str) == Some("--script") {
        let text = std::fs::read_to_string(a.get(2).expect("script file")).expect("script file");
        let (mut pending, mut tx, mut sched) = (String::new(), String::new(), String::new());
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let (c, line) = match line.strip_prefix('@') {
                Some(rest) => rest.split_once(' ').map_or((rest.to_string(), ""), |(c, l)| (c.to_string(), l)),
                None => (caller.clone(), line),
            };
            let (m, r) = line.split_once(' ').unwrap_or((line, "{}"));
            let r = r.replace("$PENDING", &pending).replace("$TX", &tx).replace("$SCHEDULE", &sched);
            let out = run(m, &r, &c);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&out) {
                if let Some(p) = v["pending_id"].as_str() { pending = p.to_string(); }
                if let Some(t) = v["tx_hash"].as_str() { tx = t.to_string(); }
                if let Some(s) = v["outcome"]["schedule"].as_str() { sched = s.to_string(); }
            }
            println!("{c}\t{m}\t{out}");
        }
        return;
    }
    let method = a.get(1).map(String::as_str).unwrap_or("version");
    let req = match a.get(2) {
        Some(r) if r.starts_with('@') => std::fs::read_to_string(&r[1..]).expect("request file"),
        Some(r) => r.clone(),
        None => "{}".to_string(),
    };
    println!("{}", run(method, &req, &caller));
}
