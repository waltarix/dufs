mod args;
mod auth;
mod log_http;
mod logger;
mod server;
mod streamer;
#[cfg(feature = "tls")]
mod tls;
#[cfg(unix)]
mod unix;
mod utils;

#[macro_use]
extern crate log;

use crate::args::print_completions;
use crate::server::{Request, Server};
#[cfg(feature = "tls")]
use crate::tls::{TlsAcceptor, TlsStream};

use anyhow::{anyhow, Result};
use clap::Parser;
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use args::{Args, BindAddr};
use futures::future::join_all;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use hyper::server::conn::{AddrIncoming, AddrStream};
use hyper::service::{make_service_fn, service_fn};
#[cfg(feature = "tls")]
use rustls::ServerConfig;

#[tokio::main]
async fn main() {
    run().await.unwrap_or_else(|err| {
        eprintln!("error: {err}");
        std::process::exit(1);
    })
}

async fn run() -> Result<()> {
    logger::init().map_err(|e| anyhow!("Failed to init logger, {e}"))?;

    let mut args = Args::parse();
    args.init()?;
    let args = args;

    if let Some(shell) = args.completions {
        print_completions(shell);
        return Ok(());
    }
    let args = Arc::new(args);
    let running = Arc::new(AtomicBool::new(true));
    let handles = serve(args.clone(), running.clone())?;
    print_listening(args)?;

    tokio::select! {
        ret = join_all(handles) => {
            for r in ret {
                if let Err(e) = r {
                    error!("{}", e);
                }
            }
            Ok(())
        },
        _ = shutdown_signal() => {
            running.store(false, Ordering::SeqCst);
            Ok(())
        },
    }
}

fn serve(
    args: Arc<Args>,
    running: Arc<AtomicBool>,
) -> Result<Vec<JoinHandle<Result<(), hyper::Error>>>> {
    let inner = Arc::new(Server::init(args.clone(), running)?);
    let mut handles = vec![];
    let port = args.port;
    for bind_addr in args.addrs.iter() {
        let inner = inner.clone();
        let serve_func = move |remote_addr: Option<SocketAddr>| {
            let inner = inner.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req: Request| {
                    let inner = inner.clone();
                    inner.call(req, remote_addr)
                }))
            }
        };
        match bind_addr {
            BindAddr::Address(ip) => {
                let incoming = create_addr_incoming(SocketAddr::new(*ip, port))
                    .map_err(|e| anyhow!("Failed to bind `{ip}:{port}`, {e}"))?;
                match &args.tls {
                    #[cfg(feature = "tls")]
                    Some((certs, key)) => {
                        let config = ServerConfig::builder()
                            .with_safe_defaults()
                            .with_no_client_auth()
                            .with_single_cert(certs.clone(), key.clone())?;
                        let config = Arc::new(config);
                        let accepter = TlsAcceptor::new(config.clone(), incoming);
                        let new_service = make_service_fn(move |socket: &TlsStream| {
                            let remote_addr = socket.remote_addr();
                            serve_func(Some(remote_addr))
                        });
                        let server =
                            tokio::spawn(hyper::Server::builder(accepter).serve(new_service));
                        handles.push(server);
                    }
                    #[cfg(not(feature = "tls"))]
                    Some(_) => {
                        unreachable!()
                    }
                    None => {
                        let new_service = make_service_fn(move |socket: &AddrStream| {
                            let remote_addr = socket.remote_addr();
                            serve_func(Some(remote_addr))
                        });
                        let server =
                            tokio::spawn(hyper::Server::builder(incoming).serve(new_service));
                        handles.push(server);
                    }
                };
            }
            BindAddr::Path(path) => {
                if path.exists() {
                    std::fs::remove_file(path)?;
                }
                #[cfg(unix)]
                {
                    let listener = tokio::net::UnixListener::bind(path)
                        .map_err(|e| anyhow!("Failed to bind `{}`, {e}", path.display()))?;
                    let acceptor = unix::UnixAcceptor::from_listener(listener);
                    let new_service = make_service_fn(move |_| serve_func(None));
                    let server = tokio::spawn(hyper::Server::builder(acceptor).serve(new_service));
                    handles.push(server);
                }
            }
        }
    }
    Ok(handles)
}

fn create_addr_incoming(addr: SocketAddr) -> Result<AddrIncoming> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024 /* Default backlog */)?;
    let std_listener = StdTcpListener::from(socket);
    std_listener.set_nonblocking(true)?;
    let incoming = AddrIncoming::from_listener(TcpListener::from_std(std_listener)?)?;
    Ok(incoming)
}

fn print_listening(args: Arc<Args>) -> Result<()> {
    let mut bind_addrs = vec![];
    let (mut ipv4, mut ipv6) = (false, false);
    for bind_addr in args.addrs.iter() {
        match bind_addr {
            BindAddr::Address(ip) => {
                if ip.is_unspecified() {
                    if ip.is_ipv6() {
                        ipv6 = true;
                    } else {
                        ipv4 = true;
                    }
                } else {
                    bind_addrs.push(bind_addr.clone());
                }
            }
            _ => bind_addrs.push(bind_addr.clone()),
        }
    }
    if ipv4 || ipv6 {
        let ifaces = if_addrs::get_if_addrs()
            .map_err(|e| anyhow!("Failed to get local interface addresses: {e}"))?;
        for iface in ifaces.into_iter() {
            let local_ip = iface.ip();
            if ipv4 && local_ip.is_ipv4() {
                bind_addrs.push(BindAddr::Address(local_ip))
            }
            if ipv6 && local_ip.is_ipv6() {
                bind_addrs.push(BindAddr::Address(local_ip))
            }
        }
    }
    bind_addrs.sort_unstable();
    let urls = bind_addrs
        .into_iter()
        .map(|bind_addr| match bind_addr {
            BindAddr::Address(addr) => {
                let addr = match addr {
                    IpAddr::V4(_) => format!("{}:{}", addr, args.port),
                    IpAddr::V6(_) => format!("[{}]:{}", addr, args.port),
                };
                let protocol = if args.tls.is_some() { "https" } else { "http" };
                format!("{}://{}{}", protocol, addr, args.uri_prefix)
            }
            BindAddr::Path(path) => path.display().to_string(),
        })
        .collect::<Vec<_>>();

    if urls.len() == 1 {
        println!("Listening on {}", urls[0]);
    } else {
        let info = urls
            .iter()
            .map(|v| format!("  {v}"))
            .collect::<Vec<String>>()
            .join("\n");
        println!("Listening on:\n{info}\n");
    }

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler")
}
