use anyhow::{anyhow, bail, Result};
use clap::{CommandFactory, Parser, ValueEnum};
use clap_complete::{generate, Generator, Shell};
use core::fmt;
#[cfg(feature = "tls")]
use rustls::{Certificate, PrivateKey};
use std::env;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::auth::AccessControl;
use crate::auth::AuthMethod;
use crate::log_http::{LogHttp, DEFAULT_LOG_FORMAT};
#[cfg(feature = "tls")]
use crate::tls::{load_certs, load_private_key};
use crate::utils::encode_uri;

#[derive(Parser, Debug)]
#[command(version, about, author)]
pub struct Args {
    /// Specific path to serve
    #[arg(
        env = "DUFS_ROOT",
        hide_env = true,
        default_value = ".",
        value_name = "root",
        value_parser = parse_path
    )]
    pub path: PathBuf,

    #[arg(skip)]
    pub path_is_file: bool,

    /// Specify bind address or unix socket
    #[arg(
        env = "DUFS_BIND",
        hide_env = true,
        name = "bind",
        short,
        long,
        default_value = "0.0.0.0,::",
        value_name = "addrs",
        value_delimiter = ',',
        value_parser = parse_addrs
    )]
    pub addrs: Vec<BindAddr>,

    /// Specify port to listen on
    #[arg(
        env = "DUFS_PORT",
        hide_env = true,
        short,
        long,
        default_value = "8080",
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

    #[arg(skip)]
    pub uri_prefix: String,

    /// Hide paths from directory listings, separated by `,`
    #[arg(
        env = "DUFS_HIDDEN",
        hide_env = true,
        long,
        value_delimiter = ',',
        value_name = "value"
    )]
    pub hidden: Vec<String>,

    /// Add auth for path
    #[arg(
        env = "DUFS_AUTH",
        hide_env = true,
        name = "auth",
        short,
        long,
        value_delimiter = ',',
        value_name = "rules"
    )]
    auth_rules: Vec<String>,

    #[arg(skip)]
    pub auth: AccessControl,

    /// Select auth method
    #[arg(
        env = "DUFS_AUTH_METHOD",
        hide_env = true,
        long,
        default_value_t = AuthMethod::Digest,
        value_name = "value"
    )]
    pub auth_method: AuthMethod,

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

    /// Use custom assets to override builtin assets
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

    #[arg(skip)]
    pub order: String,

    #[cfg(feature = "tls")]
    /// Path to an SSL/TLS certificate to serve with HTTPS
    #[arg(env = "DUFS_TLS_CERT", hide_env = true, long, value_name = "path")]
    pub tls_cert: Option<PathBuf>,

    #[cfg(feature = "tls")]
    /// Path to the SSL/TLS certificate's private key
    #[arg(env = "DUFS_TLS_KEY", hide_env = true, long, value_name = "path")]
    pub tls_key: Option<PathBuf>,

    #[cfg(feature = "tls")]
    #[arg(skip)]
    pub tls: Option<(Vec<Certificate>, PrivateKey)>,

    #[cfg(not(feature = "tls"))]
    #[arg(skip)]
    pub tls: Option<()>,

    /// Customize http log format
    #[arg(
        env = "DUFS_LOG_FORMAT",
        hide_env = true,
        long,
        default_value = DEFAULT_LOG_FORMAT,
        value_name = "format"
    )]
    pub log_format: String,

    #[arg(skip)]
    pub log_http: LogHttp,

    /// Print shell completion script for <shell>
    #[arg(long, value_name = "shell")]
    pub completions: Option<Shell>,

    #[arg(skip)]
    pub assets_path: Option<PathBuf>,
}

impl Args {
    pub fn init(&mut self) -> Result<()> {
        self.path_is_file = self.path.metadata()?.is_file();
        self.uri_prefix = self.uri_prefix();
        self.assets_path = self.assets_path()?;
        self.order = self.order();
        self.auth = self.auth()?;
        self.log_http = LogHttp::from_str(&self.log_format)?;
        self.tls = self.tls()?;
        Ok(())
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
            Some(v) => Some(Self::parse_assets_path(v)?),
            None => None,
        };
        Ok(path)
    }

    fn order(&self) -> String {
        if self.reverse { "desc" } else { "asc" }.to_owned()
    }

    fn auth(&self) -> Result<AccessControl> {
        let raw_rules: Vec<&str> = self.auth_rules.iter().map(String::as_str).collect();
        AccessControl::new(&raw_rules, &self.uri_prefix)
    }

    #[cfg(feature = "tls")]
    fn tls(&self) -> Result<Option<(Vec<Certificate>, PrivateKey)>> {
        let tls = match (&self.tls_cert, &self.tls_key) {
            (Some(certs_file), Some(key_file)) => {
                let certs = load_certs(certs_file)?;
                let key = load_private_key(key_file)?;
                Some((certs, key))
            }
            _ => None,
        };
        Ok(tls)
    }

    #[cfg(not(feature = "tls"))]
    fn tls(&self) -> Option<()> {
        None
    }

    fn parse_path<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
        let path = path.as_ref();
        if !path.exists() {
            bail!("Path `{}` doesn't exist", path.display());
        }

        env::current_dir()
            .and_then(|mut p| {
                p.push(path); // If path is absolute, it replaces the current path.
                std::fs::canonicalize(p)
            })
            .map_err(|err| anyhow!("Failed to access path `{}`: {}", path.display(), err,))
    }

    fn parse_assets_path<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
        let path = Self::parse_path(path)?;
        if !path.join("index.html").exists() {
            bail!("Path `{}` doesn't contains index.html", path.display());
        }
        Ok(path)
    }
}

pub fn print_completions<G: Generator>(gen: G) {
    let mut cmd = Args::command();
    let name = cmd.get_name().to_owned();
    generate(gen, &mut cmd, name, &mut std::io::stdout());
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BindAddr {
    Address(IpAddr),
    Path(PathBuf),
}

#[derive(Debug, Clone, ValueEnum)]
pub enum SortType {
    Name,
    Mtime,
    Size,
}

impl fmt::Display for SortType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = match self {
            SortType::Name => "name",
            SortType::Mtime => "mtime",
            SortType::Size => "size",
        };
        write!(f, "{}", v)
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

fn parse_path(path: &str) -> Result<PathBuf> {
    match Args::parse_path(path) {
        Ok(v) => Ok(v),
        Err(e) => bail!(e),
    }
}
