use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, ValueEnum};
use clap_complete::{generate, Generator, Shell};
use core::fmt;
use serde::{Deserialize, Deserializer};
use std::env;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::auth::AccessControl;
use crate::http_logger::{HttpLogger, DEFAULT_LOG_FORMAT};
use crate::utils::encode_uri;

const DEFAULT_PORT: u16 = 8080;
const DEFAULT_ADDRS: &str = "0.0.0.0,::";

#[derive(Parser, Debug, Deserialize, Default)]
#[serde(default)]
#[serde(rename_all = "kebab-case")]
#[command(version, about, author)]
pub struct Args {
    /// Specific path to serve
    #[serde(default = "default_serve_path")]
    #[arg(
        env = "DUFS_SERVE_PATH",
        hide_env = true,
        default_value = ".",
        value_name = "serve-path",
        value_parser = sanitize_path
    )]
    pub serve_path: PathBuf,

    #[serde(skip)]
    #[arg(skip)]
    pub path_is_file: bool,

    /// Specify configuration file
    #[arg(
        env = "DUFS_CONFIG",
        hide_env = true,
        short,
        long = "config",
        value_parser = sanitize_path
    )]
    pub config: Option<PathBuf>,

    /// Specify bind address or unix socket
    #[serde(deserialize_with = "deserialize_bind_addrs")]
    #[serde(rename = "bind")]
    #[serde(default = "BindAddr::default")]
    #[arg(
        env = "DUFS_BIND",
        hide_env = true,
        name = "bind",
        short,
        long,
        default_value = DEFAULT_ADDRS,
        value_name = "addrs",
        value_delimiter = ',',
        value_parser = parse_addrs
    )]
    pub addrs: Vec<BindAddr>,

    /// Specify port to listen on
    #[serde(default = "default_port")]
    #[arg(
        env = "DUFS_PORT",
        hide_env = true,
        short,
        long,
        default_value_t = DEFAULT_PORT,
        value_name = "port"
    )]
    pub port: u16,

    /// Specify a path prefix
    #[arg(
        env = "DUFS_PATH_PREFIX",
        hide_env = true,
        long,
        value_name = "path",
        default_value = "",
        value_parser = parse_path_prefix
    )]
    pub path_prefix: String,

    #[serde(skip)]
    #[arg(skip)]
    pub uri_prefix: String,

    /// Hide paths from directory listings, e.g. tmp,*.log,*.lock
    #[serde(deserialize_with = "deserialize_string_or_vec")]
    #[arg(
        env = "DUFS_HIDDEN",
        hide_env = true,
        long,
        value_delimiter = ',',
        value_name = "value"
    )]
    pub hidden: Vec<String>,

    /// Add auth role, e.g. user:pass@/dir1:rw,/dir2
    #[arg(
        env = "DUFS_AUTH",
        hide_env = true,
        name = "auth",
        short,
        long,
        value_name = "rules"
    )]
    auth_rules: Vec<String>,

    #[serde(deserialize_with = "deserialize_access_control")]
    #[arg(skip)]
    pub auth: AccessControl,

    /// Allow all operations
    #[arg(env = "DUFS_ALLOW_ALL", hide_env = true, short = 'A', long)]
    pub allow_all: bool,

    /// Allow upload files/folders
    #[arg(
        env = "DUFS_ALLOW_UPLOAD",
        hide_env = true,
        long,
        default_value_if("allow_all", "true", "true")
    )]
    pub allow_upload: bool,

    /// Allow delete files/folders
    #[arg(
        env = "DUFS_ALLOW_DELETE",
        hide_env = true,
        long,
        default_value_if("allow_all", "true", "true")
    )]
    pub allow_delete: bool,

    /// Allow search files/folders
    #[arg(
        env = "DUFS_ALLOW_SEARCH",
        hide_env = true,
        long,
        default_value_if("allow_all", "true", "true")
    )]
    pub allow_search: bool,

    /// Allow symlink to files/folders outside root directory
    #[arg(
        env = "DUFS_ALLOW_SYMLINK",
        hide_env = true,
        long,
        default_value_if("allow_all", "true", "true")
    )]
    pub allow_symlink: bool,

    /// Allow zip archive generation
    #[arg(
        env = "DUFS_ALLOW_ARCHIVE",
        hide_env = true,
        long,
        default_value_if("allow_all", "true", "true")
    )]
    pub allow_archive: bool,

    /// Enable CORS, sets `Access-Control-Allow-Origin: *`
    #[arg(env = "DUFS_ENABLE_CORS", hide_env = true, long)]
    pub enable_cors: bool,

    /// Serve index.html when requesting a directory, returns 404 if not found index.html
    #[arg(env = "DUFS_RENDER_INDEX", hide_env = true, long)]
    pub render_index: bool,

    /// Serve index.html when requesting a directory, returns directory listing if not found index.html
    #[arg(env = "DUFS_RENDER_TRY_INDEX", hide_env = true, long)]
    pub render_try_index: bool,

    /// Serve SPA(Single Page Application)
    #[arg(env = "DUFS_RENDER_SPA", hide_env = true, long)]
    pub render_spa: bool,

    /// Set the path to the assets directory for overriding the built-in assets
    #[arg(env = "DUFS_ASSETS", hide_env = true, long, value_name = "path")]
    pub assets: Option<PathBuf>,

    /// List directories first
    #[arg(env = "DUFS_DIR_FIRST", hide_env = true, short = 'D', long)]
    pub dirs_first: bool,

    /// Sort by field
    #[arg(
        short,
        long,
        value_enum,
        default_value_t = SortType::Name,
        default_value_if("latest", "true", "mtime"),
        value_name = "field"
    )]
    pub sort: SortType,

    /// Sort path by descending
    #[arg(
        env = "DUFS_REVERSE",
        hide_env = true,
        short,
        long,
        default_value_if("latest", "true", "true")
    )]
    pub reverse: bool,

    /// Sort by mtime descending order
    #[arg(env = "DUFS_LATEST", hide_env = true, long)]
    latest: bool,

    #[arg(
        hide = true,
        default_value_t = Order::Ascending,
        default_value_if("reverse", "true", "desc")
    )]
    pub order: Order,

    #[cfg(feature = "tls")]
    /// Path to an SSL/TLS certificate to serve with HTTPS
    #[arg(env = "DUFS_TLS_CERT", hide_env = true, long, value_name = "path")]
    pub tls_cert: Option<PathBuf>,

    #[cfg(feature = "tls")]
    /// Path to the SSL/TLS certificate's private key
    #[arg(env = "DUFS_TLS_KEY", hide_env = true, long, value_name = "path")]
    pub tls_key: Option<PathBuf>,

    /// Customize http log format
    #[arg(
        env = "DUFS_LOG_FORMAT",
        hide_env = true,
        long,
        default_value = DEFAULT_LOG_FORMAT,
        value_name = "format"
    )]
    pub log_format: String,

    #[serde(deserialize_with = "deserialize_log_http")]
    #[serde(rename = "log-format")]
    #[arg(skip)]
    pub http_logger: HttpLogger,

    /// Print shell completion script for <shell>
    #[serde(skip)]
    #[arg(long, value_name = "shell")]
    pub completions: Option<Shell>,

    #[arg(skip)]
    pub assets_path: Option<PathBuf>,
}

impl Args {
    pub fn init(&mut self) -> Result<&mut Self> {
        self.parse_config()?;

        self.path_is_file = self.serve_path.metadata()?.is_file();
        self.uri_prefix = self.uri_prefix();
        self.assets_path = self.assets_path()?;
        if !self.auth.exist() {
            self.auth = self.auth()?;
        }
        self.http_logger = HttpLogger::from_str(&self.log_format)?;

        #[cfg(feature = "tls")]
        {
            self.validate_tls()?;
        }
        #[cfg(not(feature = "tls"))]
        {
            self.tls_cert = None;
            self.tls_key = None;
        }

        Ok(self)
    }

    fn parse_config(&mut self) -> Result<()> {
        if let Some(config_path) = &self.config {
            let contents = std::fs::read_to_string(config_path)
                .with_context(|| format!("Failed to read config at {}", config_path.display()))?;
            let args: Self = serde_yaml::from_str(&contents)?;
            if args.serve_path.to_str().unwrap() != "." {
                self.serve_path = args.serve_path;
            }
            self.addrs = args.addrs;
            dbg!(&self.port);
            dbg!(&args.port);
            if args.port != DEFAULT_PORT {
                self.port = args.port;
            }
            self.path_prefix = args.path_prefix;
            self.auth = args.auth;
            self.auth_rules = args.auth_rules;
            self.hidden = args.hidden;
            self.allow_upload = args.allow_upload;
        }
        Ok(())
    }

    fn _config(&self) -> Result<Option<Self>> {
        if let Some(config_path) = &self.config {
            let contents = std::fs::read_to_string(config_path)
                .with_context(|| format!("Failed to read config at {}", config_path.display()))?;
            let args: Self = serde_yaml::from_str(&contents)?;
            return Ok(Some(args));
        }
        Ok(None)
    }

    #[cfg(feature = "tls")]
    fn validate_tls(&self) -> Result<()> {
        match (&self.tls_cert, &self.tls_key) {
            (Some(_), None) => bail!("No tls-key set"),
            (None, Some(_)) => bail!("No tls-cert set"),
            _ => Ok(()),
        }
    }

    fn uri_prefix(&self) -> String {
        if self.path_prefix.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}/", encode_uri(&self.path_prefix))
        }
    }
    fn assets_path(&self) -> Result<Option<PathBuf>> {
        let path = match &self.assets {
            Some(v) => Some(Self::sanitize_assets_path(v)?),
            None => None,
        };
        Ok(path)
    }

    fn auth(&self) -> Result<AccessControl> {
        let raw_rules: Vec<&str> = self.auth_rules.iter().map(String::as_str).collect();
        AccessControl::new(&raw_rules)
    }

    fn sanitize_path<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
        let path = path.as_ref();
        if !path.exists() {
            bail!("Path `{}` doesn't exist", path.display());
        }

        env::current_dir()
            .and_then(|mut p| {
                p.push(path); // If path is absolute, it replaces the current path.
                std::fs::canonicalize(p)
            })
            .with_context(|| format!("Failed to access path `{}`", path.display()))
    }

    fn sanitize_assets_path<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
        let path = Self::sanitize_path(path)?;
        if !path.join("index.html").exists() {
            bail!("Path `{}` doesn't contains index.html", path.display());
        }
        Ok(path)
    }
}

pub fn print_completions<G: Generator>(gen: G) {
    let mut cmd = Args::command();
    let name = cmd.get_name().to_owned();
    let mut buf = Vec::new();
    generate(gen, &mut cmd, name, &mut buf);

    let completion = String::from_utf8_lossy(buf.as_slice());
    // HACK: clap_complete does not support the hide flag.
    println!("{}", completion.replace("'::order:(asc desc)' \\\n", ""));
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BindAddr {
    Address(IpAddr),
    Path(PathBuf),
}

impl BindAddr {
    fn default() -> Vec<Self> {
        let addrs: Vec<&str> = DEFAULT_ADDRS.split(',').collect();
        Self::parse_addrs(&addrs[..]).unwrap()
    }

    fn parse_addrs(addrs: &[&str]) -> Result<Vec<Self>> {
        let mut bind_addrs = vec![];
        let mut invalid_addrs = vec![];
        for addr in addrs {
            match addr.parse::<IpAddr>() {
                Ok(v) => {
                    bind_addrs.push(BindAddr::Address(v));
                }
                Err(_) => {
                    if cfg!(unix) {
                        bind_addrs.push(BindAddr::Path(PathBuf::from(addr)));
                    } else {
                        invalid_addrs.push(*addr);
                    }
                }
            }
        }
        if !invalid_addrs.is_empty() {
            bail!("Invalid bind address `{}`", invalid_addrs.join(","));
        }
        Ok(bind_addrs)
    }
}

fn deserialize_bind_addrs<'de, D>(deserializer: D) -> Result<Vec<BindAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVec;

    impl<'de> serde::de::Visitor<'de> for StringOrVec {
        type Value = Vec<BindAddr>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("string or list of strings")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            BindAddr::parse_addrs(&[s]).map_err(serde::de::Error::custom)
        }

        fn visit_seq<S>(self, seq: S) -> Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            let addrs: Vec<&'de str> =
                Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))?;
            BindAddr::parse_addrs(&addrs).map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVec;

    impl<'de> serde::de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("string or list of strings")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(s.split(',').map(String::from).collect::<_>())
        }

        fn visit_seq<S>(self, seq: S) -> Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

fn deserialize_access_control<'de, D>(deserializer: D) -> Result<AccessControl, D::Error>
where
    D: Deserializer<'de>,
{
    let rules: Vec<&str> = Vec::deserialize(deserializer)?;
    AccessControl::new(&rules).map_err(serde::de::Error::custom)
}

fn deserialize_log_http<'de, D>(deserializer: D) -> Result<HttpLogger, D::Error>
where
    D: Deserializer<'de>,
{
    let value: String = Deserialize::deserialize(deserializer)?;
    value.parse().map_err(serde::de::Error::custom)
}

fn default_serve_path() -> PathBuf {
    PathBuf::from(".")
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

#[derive(Debug, Clone, ValueEnum, Default, Deserialize)]
#[value(rename_all = "lower")]
pub enum SortType {
    #[default]
    Name,
    Mtime,
    Size,
}

impl fmt::Display for SortType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_possible_value()
            .expect("no values are skipped")
            .get_name()
            .fmt(f)
    }
}

#[derive(Debug, Clone, ValueEnum, Default, Deserialize)]
pub enum Order {
    #[default]
    #[value(name = "asc")]
    Ascending,
    #[value(name = "desc")]
    Descending,
}

impl fmt::Display for Order {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_possible_value()
            .expect("no values are skipped")
            .get_name()
            .fmt(f)
    }
}

fn parse_addrs(addr: &str) -> Result<BindAddr> {
    match addr.parse::<IpAddr>() {
        Ok(v) => Ok(BindAddr::Address(v)),
        Err(e) => {
            if cfg!(unix) {
                Ok(BindAddr::Path(PathBuf::from(addr)))
            } else {
                bail!(e)
            }
        }
    }
}

fn parse_path_prefix(path_prefix: &str) -> Result<String, String> {
    Ok(path_prefix.trim_matches('/').to_owned())
}

fn sanitize_path(path: &str) -> Result<PathBuf> {
    match Args::sanitize_path(path) {
        Ok(v) => Ok(v),
        Err(e) => bail!(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_fs::prelude::*;

    #[test]
    fn test_default() {
        let args = Args::parse_from(vec![""]);
        let cwd = Args::sanitize_path(std::env::current_dir().unwrap()).unwrap();
        assert_eq!(args.serve_path, cwd);
        assert_eq!(args.port, DEFAULT_PORT);
        assert_eq!(args.addrs, BindAddr::default());
    }

    #[test]
    fn test_args_from_cli1() {
        let tmpdir = assert_fs::TempDir::new().unwrap();
        let args = Args::parse_from(vec![
            "",
            "--hidden",
            "tmp,*.log,*.lock",
            &tmpdir.to_string_lossy(),
        ]);
        assert_eq!(args.serve_path, Args::sanitize_path(&tmpdir).unwrap());
        assert_eq!(args.hidden, ["tmp", "*.log", "*.lock"]);
    }

    #[test]
    fn test_args_from_cli2() {
        let args = Args::parse_from(vec![
            "", "--hidden", "tmp", "--hidden", "*.log", "--hidden", "*.lock",
        ]);
        assert_eq!(args.hidden, ["tmp", "*.log", "*.lock"]);
    }

    #[test]
    fn test_args_from_empty_config_file() {
        let tmpdir = assert_fs::TempDir::new().unwrap();
        let config_file = tmpdir.child("config.yaml");
        config_file.write_str("").unwrap();

        let args = Args::parse_from(vec!["", "-c", &config_file.to_string_lossy()]);
        let cwd = Args::sanitize_path(std::env::current_dir().unwrap()).unwrap();
        assert_eq!(args.serve_path, cwd);
        assert_eq!(args.port, DEFAULT_PORT);
        assert_eq!(args.addrs, BindAddr::default());
    }

    #[test]
    fn test_args_from_config_file1() {
        let tmpdir = assert_fs::TempDir::new().unwrap();
        let config_file = tmpdir.child("config.yaml");
        let contents = format!(
            r#"
serve-path: {}
bind: 0.0.0.0
port: 3000
allow-upload: true
hidden: tmp,*.log,*.lock
"#,
            tmpdir.display()
        );
        config_file.write_str(&contents).unwrap();

        let mut args = Args::parse_from(vec!["", "-c", &config_file.to_string_lossy()]);
        args.init().unwrap();
        assert_eq!(args.serve_path, Args::sanitize_path(&tmpdir).unwrap());
        assert_eq!(
            args.addrs,
            vec![BindAddr::Address("0.0.0.0".parse().unwrap())]
        );
        assert_eq!(args.hidden, ["tmp", "*.log", "*.lock"]);
        assert_eq!(args.port, 3000);
        assert!(args.allow_upload);
    }

    #[test]
    fn test_args_from_config_file2() {
        let tmpdir = assert_fs::TempDir::new().unwrap();
        let config_file = tmpdir.child("config.yaml");
        let contents = r#"
bind:
  - 127.0.0.1
  - 192.168.8.10
hidden:
  - tmp
  - '*.log'
  - '*.lock'
"#;
        config_file.write_str(contents).unwrap();

        let mut args = Args::parse_from(vec!["", "-c", &config_file.to_string_lossy()]);
        args.init().unwrap();
        assert_eq!(
            args.addrs,
            vec![
                BindAddr::Address("127.0.0.1".parse().unwrap()),
                BindAddr::Address("192.168.8.10".parse().unwrap())
            ]
        );
        assert_eq!(args.hidden, ["tmp", "*.log", "*.lock"]);
    }
}
