#![allow(dead_code)]
//! Process exit codes used by dnscheck.

pub const SUCCESS: i32 = 0;
pub const GENERAL_ERROR: i32 = 1;
pub const USAGE_ERROR: i32 = 2;
pub const CONFIG_ERROR: i32 = 3;
pub const PERMISSION_ERROR: i32 = 4;
pub const NOT_FOUND: i32 = 5;
pub const INTERRUPTED: i32 = 130;

/// Findings severity that may elevate exit status for `report`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Warning = 10,
    Critical = 20,
}
