// SPDX-License-Identifier: MIT OR Apache-2.0

use std::process::Command;

fn main() {
    let text = "Slate keeps working: ssh in, clone, build, run. Build and run again.";
    let counts = rust_demo::word_counts(text);
    let data: Vec<u8> = (0..1_000_000u32).map(|i| (i % 253) as u8).collect();
    let sum = rust_demo::parallel_checksum(&data, 8);
    let child = Command::new("sh").args(["-c", "echo from-child"]).output().expect("spawn sh");
    let path = std::env::temp_dir().join("rust-demo.txt");
    std::fs::write(&path, format!("{sum}\n")).unwrap();
    let back: u64 = std::fs::read_to_string(&path).unwrap().trim().parse().unwrap();
    std::fs::remove_file(&path).unwrap();
    let ok = counts["run"] == 2 && back == sum && child.stdout == b"from-child\n";
    println!("rust-demo: words={} checksum={sum} {}", counts.len(), if ok { "ok" } else { "FAILED" });
    std::process::exit(if ok { 0 } else { 1 });
}
