//! CLI smoke tests for dnscheck.

#[test]
fn help_exits_zero() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dnscheck"))
        .arg("--help")
        .output()
        .expect("run dnscheck");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.to_lowercase().contains("dns"));
}

#[test]
fn version_flag() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dnscheck"))
        .arg("--version")
        .output()
        .expect("run");
    assert!(output.status.success());
}

#[test]
fn status_json() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dnscheck"))
        .args(["--json", "status"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert!(v.get("inspection").is_some());
}

#[test]
fn report_runs() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dnscheck"))
        .args(["--json", "report"])
        .output()
        .expect("run");
    assert!(output.status.success());
}

#[test]
fn completions_bash() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dnscheck"))
        .args(["completions", "bash"])
        .output()
        .expect("run");
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
}
