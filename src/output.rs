#![allow(dead_code)]
//! Human and JSON output helpers.

use serde::Serialize;
use std::io::{self, Write};

#[derive(Debug, Clone, Copy)]
pub struct OutputOpts {
    pub json: bool,
    pub quiet: bool,
    pub verbose: bool,
}

#[allow(dead_code)]
pub fn print_human(opts: OutputOpts, title: &str, body: &str) {
    if opts.quiet || opts.json {
        return;
    }
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "== {title} ==");
    let _ = writeln!(out, "{body}");
}

pub fn print_json<T: Serialize>(opts: OutputOpts, value: &T) -> anyhow::Result<()> {
    if !opts.json {
        return Ok(());
    }
    let s = if opts.verbose {
        serde_json::to_string_pretty(value)?
    } else {
        serde_json::to_string(value)?
    };
    println!("{s}");
    Ok(())
}

#[allow(dead_code)]
pub fn info(opts: OutputOpts, msg: &str) {
    if opts.quiet || opts.json {
        return;
    }
    eprintln!("{msg}");
}

pub fn warn_msg(opts: OutputOpts, msg: &str) {
    if opts.quiet {
        return;
    }
    if opts.json {
        tracing::warn!("{msg}");
    } else {
        eprintln!("warning: {msg}");
    }
}
