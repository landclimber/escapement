//! Writes `idl/escapement.idl.json` (`--write`), or checks that it matches the core crate (default).

fn main() {
    let (_, json) = escapement_idl::generate();
    let path = escapement_idl::idl_path();
    if std::env::args().any(|a| a == "--write") {
        std::fs::create_dir_all(path.parent().expect("idl/ has a parent")).expect("create idl/");
        std::fs::write(&path, &json).expect("write the IDL");
        println!("wrote {}", path.display());
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    if committed == json {
        println!("{} matches crates/escapement-core", path.display());
    } else {
        eprintln!(
            "{} is out of date: run `cargo run -p escapement-idl --bin idl -- --write`",
            path.display()
        );
        std::process::exit(1);
    }
}
