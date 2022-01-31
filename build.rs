use std::env;
use std::path::{Path, PathBuf};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use cargo_bpf_lib as cargo_bpf;

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let cargo = PathBuf::from(env::var("CARGO").unwrap());
    let target = PathBuf::from(env::var("OUT_DIR").unwrap());
    let probes = Path::new("./probes");

    if let Err(e) = cargo_bpf::build_with_features(
        &cargo,
        probes,
        &target.join("target"),
        &mut Vec::new(),
        &vec![String::from("probes")],
    ) {
        eprintln!("{}", e);
        panic!("probes build failed");
    }

    cargo_bpf::probe_files(probes)
        .expect("couldn't list probe files")
        .iter()
        .for_each(|file| {
            println!("cargo:rerun-if-changed={}", file);
        });
    println!("cargo:rerun-if-changed=./probes/Cargo.toml");
}
