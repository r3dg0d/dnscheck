//! XDG-aware configuration loading.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Known ISP / public resolver prefixes to flag as potential leaks.
    #[serde(default)]
    pub known_isp_resolvers: Vec<String>,
    /// Domains used when `--probe` is enabled.
    #[serde(default = "default_probe_domains")]
    pub probe_domains: Vec<String>,
    /// Extra notes shown in reports.
    #[serde(default)]
    pub notes: Option<String>,
}

fn default_probe_domains() -> Vec<String> {
    vec!["whoami.akamai.net".into(), "o-o.myaddr.l.google.com".into()]
}

impl Config {
    pub fn load(explicit: Option<&Path>) -> Result<(Self, Option<PathBuf>)> {
        if let Some(p) = explicit {
            let text =
                fs::read_to_string(p).with_context(|| format!("reading config {}", p.display()))?;
            let cfg: Config = serde_json::from_str(&text)
                .with_context(|| format!("parsing config {}", p.display()))?;
            return Ok((cfg, Some(p.to_path_buf())));
        }

        if let Some(dirs) = ProjectDirs::from("dev", "r3dg0d", "dnscheck") {
            let path = dirs.config_dir().join("config.json");
            if path.exists() {
                let text = fs::read_to_string(&path)
                    .with_context(|| format!("reading config {}", path.display()))?;
                let cfg: Config = serde_json::from_str(&text)
                    .with_context(|| format!("parsing config {}", path.display()))?;
                return Ok((cfg, Some(path)));
            }
        }

        Ok((Config::default(), None))
    }

    #[allow(dead_code)]
    pub fn data_dir() -> Option<PathBuf> {
        ProjectDirs::from("dev", "r3dg0d", "dnscheck").map(|d| d.data_dir().to_path_buf())
    }

    #[allow(dead_code)]
    pub fn config_dir() -> Option<PathBuf> {
        ProjectDirs::from("dev", "r3dg0d", "dnscheck").map(|d| d.config_dir().to_path_buf())
    }
}
