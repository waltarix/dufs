use crate::args::{Args, SortType};
use crate::streamer::Streamer;
use crate::utils::{decode_uri, encode_uri, get_file_name, glob, try_get_file_name};
use crate::BoxResult;
use walkdir::WalkDir;
use xml::escape::escape_str_pcdata;

use async_zip::write::{EntryOptions, ZipFileWriter};
use async_zip::Compression;
use chrono::{TimeZone, Utc};
use futures::TryStreamExt;
use headers::{
    AcceptRanges, AccessControlAllowCredentials, AccessControlAllowOrigin, Connection,
    ContentLength, ContentType, ETag, HeaderMap, HeaderMapExt, IfModifiedSince, IfNoneMatch,
    IfRange, LastModified, Range,
};
use hyper::header::{
    HeaderValue, AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE,
    RANGE, WWW_AUTHENTICATE,
};
use hyper::{Body, Method, StatusCode, Uri};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::Metadata;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWrite};
use tokio::{fs, io};
use tokio_util::io::StreamReader;
use uuid::Uuid;

use clap::ValueEnum;

pub type Request = hyper::Request<Body>;
pub type Response = hyper::Response<Body>;

const INDEX_HTML: &str = include_str!("../assets/index.html");
const INDEX_CSS: &str = include_str!("../assets/index.css");
const INDEX_JS: &str = include_str!("../assets/index.js");
const FAVICON_ICO: &[u8] = include_bytes!("../assets/favicon.ico");
const INDEX_NAME: &str = "index.html";
const BUF_SIZE: usize = 65536;

pub struct Server {
    args: Arc<Args>,
    assets_prefix: String,
    html: Cow<'static, str>,
    single_file_req_paths: Vec<String>,
    running: Arc<AtomicBool>,
}

impl Server {
    pub fn new(args: Arc<Args>, running: Arc<AtomicBool>) -> Self {
        let assets_prefix = format!("{}__dufs_v{}_", args.uri_prefix, env!("CARGO_PKG_VERSION"));
        let single_file_req_paths = if args.path_is_file {
            vec![
                args.uri_prefix.to_string(),
                args.uri_prefix[0..args.uri_prefix.len() - 1].to_string(),
                encode_uri(&format!(
                    "{}{}",
                    &args.uri_prefix,
                    get_file_name(&args.path)
                )),
            ]
        } else {
            vec![]
        };
        let html = match args.assets_path.as_ref() {
            Some(path) => Cow::Owned(std::fs::read_to_string(path.join("index.html")).unwrap()),
            None => Cow::Borrowed(INDEX_HTML),
        };
        Self {
            args,
            running,
            single_file_req_paths,
            assets_prefix,
            html,
        }
    }

    pub async fn call(
        self: Arc<Self>,
        req: Request,
        addr: Option<SocketAddr>,
    ) -> Result<Response, hyper::Error> {
        let uri = req.uri().clone();
        let assets_prefix = self.assets_prefix.clone();
        let enable_cors = self.args.enable_cors;
        let mut http_log_data = self.args.log_http.data(&req, &self.args);
        if let Some(addr) = addr {
            http_log_data.insert("remote_addr".to_string(), addr.ip().to_string());
        }

        let mut res = match self.clone().handle(req).await {
            Ok(res) => {
                http_log_data.insert("status".to_string(), res.status().as_u16().to_string());
                if !uri.path().starts_with(&assets_prefix) {
                    self.args.log_http.log(&http_log_data, None);
                }
                res
            }
            Err(err) => {
                let mut res = Response::default();
                let status = StatusCode::INTERNAL_SERVER_ERROR;
                *res.status_mut() = status;
                http_log_data.insert("status".to_string(), status.as_u16().to_string());
                self.args
                    .log_http
                    .log(&http_log_data, Some(err.to_string()));
                res
            }
        };

        if enable_cors {
            add_cors(&mut res);
        }
        Ok(res)
    }

    pub async fn handle(self: Arc<Self>, req: Request) -> BoxResult<Response> {
        let mut res = Response::default();

        let req_path = req.uri().path();
        let headers = req.headers();
        let method = req.method().clone();

        if method == Method::GET && self.handle_assets(req_path, headers, &mut res).await? {
            return Ok(res);
        }

        let authorization = headers.get(AUTHORIZATION);
        let guard_type = self.args.auth.guard(
            req_path,
            &method,
            authorization,
            self.args.auth_method.clone(),
        );
        if guard_type.is_reject() {
            self.auth_reject(&mut res);
            return Ok(res);
        }

        let head_only = method == Method::HEAD;

        if self.args.path_is_file {
            if self
                .single_file_req_paths
                .iter()
                .any(|v| v.as_str() == req_path)
            {
                self.handle_send_file(&self.args.path, headers, head_only, &mut res)
                    .await?;
            } else {
                status_not_found(&mut res);
            }
            return Ok(res);
        }

        let path = match self.extract_path(req_path) {
            Some(v) => v,
            None => {
                status_forbid(&mut res);
                return Ok(res);
            }
        };

        let path = path.as_path();

        let query = req.uri().query().unwrap_or_default();
        let query_params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let (is_miss, is_dir, is_file, size) = match fs::metadata(path).await.ok() {
            Some(meta) => (false, meta.is_dir(), meta.is_file(), meta.len()),
            None => (true, false, false, 0),
        };

        let allow_upload = self.args.allow_upload;
        let allow_delete = self.args.allow_delete;
        let allow_search = self.args.allow_search;
        let render_index = self.args.render_index;
        let render_spa = self.args.render_spa;
        let render_try_index = self.args.render_try_index;

        if !self.args.allow_symlink && !is_miss && !self.is_root_contained(path).await {
            status_not_found(&mut res);
            return Ok(res);
        }

        match method {
            Method::GET | Method::HEAD => {
                if is_dir {
                    if render_try_index {
                        if query_params.contains_key("zip") {
                            self.handle_zip_dir(path, head_only, &mut res).await?;
                        } else if allow_search && query_params.contains_key("q") {
                            self.handle_search_dir(path, &query_params, head_only, &mut res)
                                .await?;
                        } else {
                            self.handle_render_index(
                                path,
                                &query_params,
                                headers,
                                head_only,
                                &mut res,
                            )
                            .await?;
                        }
                    } else if render_index || render_spa {
                        self.handle_render_index(path, &query_params, headers, head_only, &mut res)
                            .await?;
                    } else if query_params.contains_key("zip") {
                        self.handle_zip_dir(path, head_only, &mut res).await?;
                    } else if allow_search && query_params.contains_key("q") {
                        self.handle_search_dir(path, &query_params, head_only, &mut res)
                            .await?;
                    } else {
                        self.handle_ls_dir(path, true, &query_params, head_only, &mut res)
                            .await?;
                    }
                } else if is_file {
                    self.handle_send_file(path, headers, head_only, &mut res)
                        .await?;
                } else if render_spa {
                    self.handle_render_spa(path, headers, head_only, &mut res)
                        .await?;
                } else if allow_upload && req_path.ends_with('/') {
                    self.handle_ls_dir(path, false, &query_params, head_only, &mut res)
                        .await?;
                } else {
                    status_not_found(&mut res);
                }
            }
            Method::OPTIONS => {
                set_webdav_headers(&mut res);
            }
            Method::PUT => {
                if !allow_upload || (!allow_delete && is_file && size > 0) {
                    status_forbid(&mut res);
                } else {
                    self.handle_upload(path, req, &mut res).await?;
                }
            }
            Method::DELETE => {
                if !allow_delete {
                    status_forbid(&mut res);
                } else if !is_miss {
                    self.handle_delete(path, is_dir, &mut res).await?
                } else {
                    status_not_found(&mut res);
                }
            }
            method => match method.as_str() {
                "PROPFIND" => {
                    if is_dir {
                        self.handle_propfind_dir(path, headers, &mut res).await?;
                    } else if is_file {
                        self.handle_propfind_file(path, &mut res).await?;
                    } else {
                        status_not_found(&mut res);
                    }
                }
                "PROPPATCH" => {
                    if is_file {
                        self.handle_proppatch(req_path, &mut res).await?;
                    } else {
                        status_not_found(&mut res);
                    }
                }
                "MKCOL" => {
                    if !allow_upload {
                        status_forbid(&mut res);
                    } else if !is_miss {
                        *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                        *res.body_mut() = Body::from("Already exists");
                    } else {
                        self.handle_mkcol(path, &mut res).await?;
                    }
                }
                "COPY" => {
                    if !allow_upload {
                        status_forbid(&mut res);
                    } else if is_miss {
                        status_not_found(&mut res);
                    } else {
                        self.handle_copy(path, &req, &mut res).await?
                    }
                }
                "MOVE" => {
                    if !allow_upload || !allow_delete {
                        status_forbid(&mut res);
                    } else if is_miss {
                        status_not_found(&mut res);
                    } else {
                        self.handle_move(path, &req, &mut res).await?
                    }
                }
                "LOCK" => {
                    // Fake lock
                    if is_file {
                        let has_auth = authorization.is_some();
                        self.handle_lock(req_path, has_auth, &mut res).await?;
                    } else {
                        status_not_found(&mut res);
                    }
                }
                "UNLOCK" => {
                    // Fake unlock
                    if is_miss {
                        status_not_found(&mut res);
                    }
                }
                _ => {
                    *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                }
            },
        }
        Ok(res)
    }

    async fn handle_upload(
        &self,
        path: &Path,
        mut req: Request,
        res: &mut Response,
    ) -> BoxResult<()> {
        ensure_path_parent(path).await?;

        let mut file = match fs::File::create(&path).await {
            Ok(v) => v,
            Err(_) => {
                status_forbid(res);
                return Ok(());
            }
        };

        let body_with_io_error = req
            .body_mut()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err));

        let body_reader = StreamReader::new(body_with_io_error);

        futures::pin_mut!(body_reader);

        io::copy(&mut body_reader, &mut file).await?;

        *res.status_mut() = StatusCode::CREATED;
        Ok(())
    }

    async fn handle_delete(&self, path: &Path, is_dir: bool, res: &mut Response) -> BoxResult<()> {
        match is_dir {
            true => fs::remove_dir_all(path).await?,
            false => fs::remove_file(path).await?,
        }

        status_no_content(res);
        Ok(())
    }

    async fn handle_ls_dir(
        &self,
        path: &Path,
        exist: bool,
        query_params: &HashMap<String, String>,
        head_only: bool,
        res: &mut Response,
    ) -> BoxResult<()> {
        let mut paths = vec![];
        if exist {
            paths = match self.list_dir(path, path).await {
                Ok(paths) => paths,
                Err(_) => {
                    status_forbid(res);
                    return Ok(());
                }
            }
        };
        self.send_index(path, paths, exist, query_params, head_only, res)
    }

    async fn handle_search_dir(
        &self,
        path: &Path,
        query_params: &HashMap<String, String>,
        head_only: bool,
        res: &mut Response,
    ) -> BoxResult<()> {
        let mut paths: Vec<PathItem> = vec![];
        let search = query_params.get("q").unwrap().to_lowercase();
        if !search.is_empty() {
            let path_buf = path.to_path_buf();
            let hidden = Arc::new(self.args.hidden.to_vec());
            let hidden = hidden.clone();
            let running = self.running.clone();
            let search_paths = tokio::task::spawn_blocking(move || {
                let mut it = WalkDir::new(&path_buf).into_iter();
                let mut paths: Vec<PathBuf> = vec![];
                while let Some(Ok(entry)) = it.next() {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    let entry_path = entry.path();
                    let base_name = get_file_name(entry_path);
                    let file_type = entry.file_type();
                    if is_hidden(&hidden, base_name) {
                        if file_type.is_dir() {
                            it.skip_current_dir();
                        }
                        continue;
                    }
                    if !base_name.to_lowercase().contains(&search) {
                        continue;
                    }
                    if entry.path().symlink_metadata().is_err() {
                        continue;
                    }
                    paths.push(entry_path.to_path_buf());
                }
                paths
            })
            .await?;
            for search_path in search_paths.into_iter() {
                if let Ok(Some(item)) = self.to_pathitem(search_path, path.to_path_buf()).await {
                    paths.push(item);
                }
            }
        }
        self.send_index(path, paths, true, query_params, head_only, res)
    }

    async fn handle_zip_dir(
        &self,
        path: &Path,
        head_only: bool,
        res: &mut Response,
    ) -> BoxResult<()> {
        let (mut writer, reader) = tokio::io::duplex(BUF_SIZE);
        let filename = try_get_file_name(path)?;
        res.headers_mut().insert(
            CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!(
                "attachment; filename=\"{}.zip\"",
                encode_uri(filename),
            ))
            .unwrap(),
        );
        res.headers_mut()
            .insert("content-type", HeaderValue::from_static("application/zip"));
        if head_only {
            return Ok(());
        }
        let path = path.to_owned();
        let hidden = self.args.hidden.clone();
        let running = self.running.clone();
        tokio::spawn(async move {
            if let Err(e) = zip_dir(&mut writer, &path, &hidden, running).await {
                error!("Failed to zip {}, {}", path.display(), e);
            }
        });
        let reader = Streamer::new(reader, BUF_SIZE);
        *res.body_mut() = Body::wrap_stream(reader.into_stream());
        Ok(())
    }

    async fn handle_render_index(
        &self,
        path: &Path,
        query_params: &HashMap<String, String>,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> BoxResult<()> {
        let index_path = path.join(INDEX_NAME);
        if fs::metadata(&index_path)
            .await
            .ok()
            .map(|v| v.is_file())
            .unwrap_or_default()
        {
            self.handle_send_file(&index_path, headers, head_only, res)
                .await?;
        } else if self.args.render_try_index {
            self.handle_ls_dir(path, true, query_params, head_only, res)
                .await?;
        } else {
            status_not_found(res)
        }
        Ok(())
    }

    async fn handle_render_spa(
        &self,
        path: &Path,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> BoxResult<()> {
        if path.extension().is_none() {
            let path = self.args.path.join(INDEX_NAME);
            self.handle_send_file(&path, headers, head_only, res)
                .await?;
        } else {
            status_not_found(res)
        }
        Ok(())
    }

    async fn handle_assets(
        &self,
        req_path: &str,
        headers: &HeaderMap<HeaderValue>,
        res: &mut Response,
    ) -> BoxResult<bool> {
        if let Some(name) = req_path.strip_prefix(&self.assets_prefix) {
            match self.args.assets_path.as_ref() {
                Some(assets_path) => {
                    let path = assets_path.join(name);
                    self.handle_send_file(&path, headers, false, res).await?;
                }
                None => match name {
                    "index.js" => {
                        *res.body_mut() = Body::from(INDEX_JS);
                        res.headers_mut().insert(
                            "content-type",
                            HeaderValue::from_static("application/javascript"),
                        );
                    }
                    "index.css" => {
                        *res.body_mut() = Body::from(INDEX_CSS);
                        res.headers_mut()
                            .insert("content-type", HeaderValue::from_static("text/css"));
                    }
                    "favicon.ico" => {
                        *res.body_mut() = Body::from(FAVICON_ICO);
                        res.headers_mut()
                            .insert("content-type", HeaderValue::from_static("image/x-icon"));
                    }
                    _ => {
                        status_not_found(res);
                    }
                },
            }
            res.headers_mut().insert(
                "cache-control",
                HeaderValue::from_static("max-age=2592000, public"),
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn handle_send_file(
        &self,
        path: &Path,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> BoxResult<()> {
        let (file, meta) = tokio::join!(fs::File::open(path), fs::metadata(path),);
        let (mut file, meta) = (file?, meta?);
        let mut use_range = true;
        if let Some((etag, last_modified)) = extract_cache_headers(&meta) {
            let cached = {
                if let Some(if_none_match) = headers.typed_get::<IfNoneMatch>() {
                    !if_none_match.precondition_passes(&etag)
                } else if let Some(if_modified_since) = headers.typed_get::<IfModifiedSince>() {
                    !if_modified_since.is_modified(last_modified.into())
                } else {
                    false
                }
            };
            if cached {
                *res.status_mut() = StatusCode::NOT_MODIFIED;
                return Ok(());
            }

            res.headers_mut().typed_insert(last_modified);
            res.headers_mut().typed_insert(etag.clone());

            if headers.typed_get::<Range>().is_some() {
                use_range = headers
                    .typed_get::<IfRange>()
                    .map(|if_range| !if_range.is_modified(Some(&etag), Some(&last_modified)))
                    // Always be fresh if there is no validators
                    .unwrap_or(true);
            } else {
                use_range = false;
            }
        }

        let range = if use_range {
            parse_range(headers)
        } else {
            None
        };

        match mime_guess::from_path(path).first() {
            Some(mime) => {
                match (mime.type_(), mime.subtype()) {
                    (mime_guess::mime::TEXT, mime_guess::mime::PLAIN) => res
                        .headers_mut()
                        .typed_insert(ContentType::from(mime_guess::mime::TEXT_PLAIN_UTF_8)),
                    _ => res.headers_mut().typed_insert(ContentType::from(mime)),
                };
            }
            _ => {
                res.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                );
            }
        };

        let filename = try_get_file_name(path)?;
        res.headers_mut().insert(
            CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("inline; filename=\"{}\"", encode_uri(filename),))
                .unwrap(),
        );

        res.headers_mut().typed_insert(AcceptRanges::bytes());

        let size = meta.len();

        if let Some(range) = range {
            if range
                .end
                .map_or_else(|| range.start < size, |v| v >= range.start)
                && file.seek(SeekFrom::Start(range.start)).await.is_ok()
            {
                let end = range.end.unwrap_or(size - 1).min(size - 1);
                let part_size = end - range.start + 1;
                let reader = Streamer::new(file, BUF_SIZE);
                *res.status_mut() = StatusCode::PARTIAL_CONTENT;
                let content_range = format!("bytes {}-{}/{}", range.start, end, size);
                res.headers_mut()
                    .insert(CONTENT_RANGE, content_range.parse().unwrap());
                res.headers_mut()
                    .insert(CONTENT_LENGTH, format!("{}", part_size).parse().unwrap());
                if head_only {
                    return Ok(());
                }
                *res.body_mut() = Body::wrap_stream(reader.into_stream_sized(part_size));
            } else {
                *res.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                res.headers_mut()
                    .insert(CONTENT_RANGE, format!("bytes */{}", size).parse().unwrap());
            }
        } else {
            res.headers_mut()
                .insert(CONTENT_LENGTH, format!("{}", size).parse().unwrap());
            if head_only {
                return Ok(());
            }
            let reader = Streamer::new(file, BUF_SIZE);
            *res.body_mut() = Body::wrap_stream(reader.into_stream());
        }
        Ok(())
    }

    async fn handle_propfind_dir(
        &self,
        path: &Path,
        headers: &HeaderMap<HeaderValue>,
        res: &mut Response,
    ) -> BoxResult<()> {
        let depth: u32 = match headers.get("depth") {
            Some(v) => match v.to_str().ok().and_then(|v| v.parse().ok()) {
                Some(v) => v,
                None => {
                    *res.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(());
                }
            },
            None => 1,
        };
        let mut paths = vec![self.to_pathitem(path, &self.args.path).await?.unwrap()];
        if depth != 0 {
            match self.list_dir(path, &self.args.path).await {
                Ok(child) => paths.extend(child),
                Err(_) => {
                    status_forbid(res);
                    return Ok(());
                }
            }
        }
        let output = paths
            .iter()
            .map(|v| v.to_dav_xml(self.args.uri_prefix.as_str()))
            .fold(String::new(), |mut acc, v| {
                acc.push_str(&v);
                acc
            });
        res_multistatus(res, &output);
        Ok(())
    }

    async fn handle_propfind_file(&self, path: &Path, res: &mut Response) -> BoxResult<()> {
        if let Some(pathitem) = self.to_pathitem(path, &self.args.path).await? {
            res_multistatus(res, &pathitem.to_dav_xml(self.args.uri_prefix.as_str()));
        } else {
            status_not_found(res);
        }
        Ok(())
    }

    async fn handle_mkcol(&self, path: &Path, res: &mut Response) -> BoxResult<()> {
        fs::create_dir_all(path).await?;
        *res.status_mut() = StatusCode::CREATED;
        Ok(())
    }

    async fn handle_copy(&self, path: &Path, req: &Request, res: &mut Response) -> BoxResult<()> {
        let dest = match self.extract_dest(req, res) {
            Some(dest) => dest,
            None => {
                return Ok(());
            }
        };

        let meta = fs::symlink_metadata(path).await?;
        if meta.is_dir() {
            status_forbid(res);
            return Ok(());
        }

        ensure_path_parent(&dest).await?;

        fs::copy(path, &dest).await?;

        status_no_content(res);
        Ok(())
    }

    async fn handle_move(&self, path: &Path, req: &Request, res: &mut Response) -> BoxResult<()> {
        let dest = match self.extract_dest(req, res) {
            Some(dest) => dest,
            None => {
                return Ok(());
            }
        };

        ensure_path_parent(&dest).await?;

        fs::rename(path, &dest).await?;

        status_no_content(res);
        Ok(())
    }

    async fn handle_lock(&self, req_path: &str, auth: bool, res: &mut Response) -> BoxResult<()> {
        let token = if auth {
            format!("opaquelocktoken:{}", Uuid::new_v4())
        } else {
            Utc::now().timestamp().to_string()
        };

        res.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("application/xml; charset=utf-8"),
        );
        res.headers_mut()
            .insert("lock-token", format!("<{}>", token).parse().unwrap());

        *res.body_mut() = Body::from(format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>
<D:locktoken><D:href>{}</D:href></D:locktoken>
<D:lockroot><D:href>{}</D:href></D:lockroot>
</D:activelock></D:lockdiscovery></D:prop>"#,
            token, req_path
        ));
        Ok(())
    }

    async fn handle_proppatch(&self, req_path: &str, res: &mut Response) -> BoxResult<()> {
        let output = format!(
            r#"<D:response>
<D:href>{}</D:href>
<D:propstat>
<D:prop>
</D:prop>
<D:status>HTTP/1.1 403 Forbidden</D:status>
</D:propstat>
</D:response>"#,
            req_path
        );
        res_multistatus(res, &output);
        Ok(())
    }

    fn send_index(
        &self,
        path: &Path,
        mut paths: Vec<PathItem>,
        exist: bool,
        query_params: &HashMap<String, String>,
        head_only: bool,
        res: &mut Response,
    ) -> BoxResult<()> {
        let sort = match SortType::from_str(query_params.get("sort").unwrap_or(&"".into()), true) {
            Ok(s) => s,
            Err(_) => self.args.sort.clone(),
        };
        match sort {
            SortType::Name => paths.sort_by(|v1, v2| {
                alphanumeric_sort::compare_str(v1.name.to_lowercase(), v2.name.to_lowercase())
            }),
            SortType::Mtime => paths.sort_by(|v1, v2| v1.mtime.cmp(&v2.mtime)),
            SortType::Size => {
                paths.sort_by(|v1, v2| v1.size.unwrap_or(0).cmp(&v2.size.unwrap_or(0)))
            }
        }
        let order = query_params
            .get("order")
            .map_or(self.args.order.clone(), String::clone);
        if order == "desc" {
            paths.reverse()
        }
        if self.args.dirs_first {
            paths.sort_by_key(|e| !e.is_dir())
        }
        let href = format!("/{}", normalize_path(path.strip_prefix(&self.args.path)?));
        let data = IndexData {
            href,
            uri_prefix: self.args.uri_prefix.clone(),
            paths,
            allow_upload: self.args.allow_upload,
            allow_delete: self.args.allow_delete,
            allow_search: self.args.allow_search,
            dir_exists: exist,
            sort: sort.to_string(),
            order,
        };
        let data = serde_json::to_string(&data).unwrap();
        let output = self
            .html
            .replace("__ASSERTS_PREFIX__", &self.assets_prefix)
            .replace("__INDEX_DATA__", &data);
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
        res.headers_mut()
            .typed_insert(ContentLength(output.as_bytes().len() as u64));
        if head_only {
            return Ok(());
        }
        *res.body_mut() = output.into();
        Ok(())
    }

    fn auth_reject(&self, res: &mut Response) {
        let value = self.args.auth_method.www_auth(false);
        set_webdav_headers(res);
        res.headers_mut().typed_insert(Connection::close());
        res.headers_mut()
            .insert(WWW_AUTHENTICATE, value.parse().unwrap());
        *res.status_mut() = StatusCode::UNAUTHORIZED;
    }

    async fn is_root_contained(&self, path: &Path) -> bool {
        fs::canonicalize(path)
            .await
            .ok()
            .map(|v| v.starts_with(&self.args.path))
            .unwrap_or_default()
    }

    fn extract_dest(&self, req: &Request, res: &mut Response) -> Option<PathBuf> {
        let headers = req.headers();
        let dest_path = match self.extract_destination_header(headers) {
            Some(dest) => dest,
            None => {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                return None;
            }
        };
        let authorization = headers.get(AUTHORIZATION);
        let guard_type = self.args.auth.guard(
            &dest_path,
            req.method(),
            authorization,
            self.args.auth_method.clone(),
        );
        if guard_type.is_reject() {
            *res.status_mut() = StatusCode::FORBIDDEN;
            *res.body_mut() = Body::from("Forbidden");
            return None;
        }

        let dest = match self.extract_path(&dest_path) {
            Some(dest) => dest,
            None => {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                return None;
            }
        };

        Some(dest)
    }

    fn extract_destination_header(&self, headers: &HeaderMap<HeaderValue>) -> Option<String> {
        let dest = headers.get("Destination")?.to_str().ok()?;
        let uri: Uri = dest.parse().ok()?;
        Some(uri.path().to_string())
    }

    fn extract_path(&self, path: &str) -> Option<PathBuf> {
        let mut slash_stripped_path = path;
        while let Some(p) = slash_stripped_path.strip_prefix('/') {
            slash_stripped_path = p
        }
        let decoded_path = decode_uri(slash_stripped_path)?;
        let slashes_switched = if cfg!(windows) {
            decoded_path.replace('/', "\\")
        } else {
            decoded_path.into_owned()
        };
        let stripped_path = match self.strip_path_prefix(&slashes_switched) {
            Some(path) => path,
            None => return None,
        };
        Some(self.args.path.join(stripped_path))
    }

    fn strip_path_prefix<'a, P: AsRef<Path>>(&self, path: &'a P) -> Option<&'a Path> {
        let path = path.as_ref();
        if self.args.path_prefix.is_empty() {
            Some(path)
        } else {
            path.strip_prefix(&self.args.path_prefix).ok()
        }
    }

    async fn list_dir(&self, entry_path: &Path, base_path: &Path) -> BoxResult<Vec<PathItem>> {
        let mut paths: Vec<PathItem> = vec![];
        let mut rd = fs::read_dir(entry_path).await?;
        while let Ok(Some(entry)) = rd.next_entry().await {
            let entry_path = entry.path();
            let base_name = get_file_name(&entry_path);
            if is_hidden(&self.args.hidden, base_name) {
                continue;
            }
            if let Ok(Some(item)) = self.to_pathitem(entry_path.as_path(), base_path).await {
                paths.push(item);
            }
        }
        Ok(paths)
    }

    async fn to_pathitem<P: AsRef<Path>>(
        &self,
        path: P,
        base_path: P,
    ) -> BoxResult<Option<PathItem>> {
        let path = path.as_ref();
        let rel_path = path.strip_prefix(base_path).unwrap();
        let (meta, meta2) = tokio::join!(fs::metadata(&path), fs::symlink_metadata(&path));
        let (meta, meta2) = (meta?, meta2?);
        let is_symlink = meta2.is_symlink();
        if !self.args.allow_symlink && is_symlink && !self.is_root_contained(path).await {
            return Ok(None);
        }
        let is_dir = meta.is_dir();
        let path_type = match (is_symlink, is_dir) {
            (true, true) => PathType::SymlinkDir,
            (false, true) => PathType::Dir,
            (true, false) => PathType::SymlinkFile,
            (false, false) => PathType::File,
        };
        let mtime = to_timestamp(&meta.modified()?);
        let size = match path_type {
            PathType::Dir | PathType::SymlinkDir => None,
            PathType::File | PathType::SymlinkFile => Some(meta.len()),
        };
        let name = normalize_path(rel_path);
        Ok(Some(PathItem {
            path_type,
            name,
            mtime,
            size,
        }))
    }
}

#[derive(Debug, Serialize)]
struct IndexData {
    href: String,
    uri_prefix: String,
    paths: Vec<PathItem>,
    allow_upload: bool,
    allow_delete: bool,
    allow_search: bool,
    dir_exists: bool,
    sort: String,
    order: String,
}

#[derive(Debug, Serialize, Eq, PartialEq, Ord, PartialOrd)]
struct PathItem {
    path_type: PathType,
    name: String,
    mtime: u64,
    size: Option<u64>,
}

impl PathItem {
    pub fn is_dir(&self) -> bool {
        self.path_type == PathType::Dir || self.path_type == PathType::SymlinkDir
    }

    pub fn to_dav_xml(&self, prefix: &str) -> String {
        let mtime = Utc.timestamp_millis(self.mtime as i64).to_rfc2822();
        let mut href = encode_uri(&format!("{}{}", prefix, &self.name));
        if self.is_dir() && !href.ends_with('/') {
            href.push('/');
        }
        let displayname = escape_str_pcdata(self.base_name());
        match self.path_type {
            PathType::Dir | PathType::SymlinkDir => format!(
                r#"<D:response>
<D:href>{}</D:href>
<D:propstat>
<D:prop>
<D:displayname>{}</D:displayname>
<D:getlastmodified>{}</D:getlastmodified>
<D:resourcetype><D:collection/></D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"#,
                href, displayname, mtime
            ),
            PathType::File | PathType::SymlinkFile => format!(
                r#"<D:response>
<D:href>{}</D:href>
<D:propstat>
<D:prop>
<D:displayname>{}</D:displayname>
<D:getcontentlength>{}</D:getcontentlength>
<D:getlastmodified>{}</D:getlastmodified>
<D:resourcetype></D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"#,
                href,
                displayname,
                self.size.unwrap_or_default(),
                mtime
            ),
        }
    }
    pub fn base_name(&self) -> &str {
        self.name.split('/').last().unwrap_or_default()
    }
}

#[derive(Debug, Serialize, Eq, PartialEq, Ord, PartialOrd)]
enum PathType {
    Dir,
    SymlinkDir,
    File,
    SymlinkFile,
}

fn to_timestamp(time: &SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn normalize_path<P: AsRef<Path>>(path: P) -> String {
    let path = path.as_ref().to_str().unwrap_or_default();
    if cfg!(windows) {
        path.replace('\\', "/")
    } else {
        path.to_string()
    }
}

async fn ensure_path_parent(path: &Path) -> BoxResult<()> {
    if let Some(parent) = path.parent() {
        if fs::symlink_metadata(parent).await.is_err() {
            fs::create_dir_all(&parent).await?;
        }
    }
    Ok(())
}

fn add_cors(res: &mut Response) {
    res.headers_mut()
        .typed_insert(AccessControlAllowOrigin::ANY);
    res.headers_mut()
        .typed_insert(AccessControlAllowCredentials);
    res.headers_mut().insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static("GET,HEAD,PUT,OPTIONS,DELETE,PROPFIND,COPY,MOVE"),
    );
    res.headers_mut().insert(
        "Access-Control-Allow-Headers",
        HeaderValue::from_static("Authorization,Destination,Range"),
    );
    res.headers_mut().insert(
        "Access-Control-Expose-Headers",
        HeaderValue::from_static(
            "WWW-Authenticate,Content-Range,Accept-Ranges,Content-Disposition",
        ),
    );
}

fn res_multistatus(res: &mut Response, content: &str) {
    *res.status_mut() = StatusCode::MULTI_STATUS;
    res.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    *res.body_mut() = Body::from(format!(
        r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
{}
</D:multistatus>"#,
        content,
    ));
}

async fn zip_dir<W: AsyncWrite + Unpin>(
    writer: &mut W,
    dir: &Path,
    hidden: &[String],
    running: Arc<AtomicBool>,
) -> BoxResult<()> {
    let mut writer = ZipFileWriter::new(writer);
    let hidden = Arc::new(hidden.to_vec());
    let hidden = hidden.clone();
    let dir_path_buf = dir.to_path_buf();
    let zip_paths = tokio::task::spawn_blocking(move || {
        let mut it = WalkDir::new(&dir_path_buf).into_iter();
        let mut paths: Vec<PathBuf> = vec![];
        while let Some(Ok(entry)) = it.next() {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            let entry_path = entry.path();
            let base_name = get_file_name(entry_path);
            let file_type = entry.file_type();
            if is_hidden(&hidden, base_name) {
                if file_type.is_dir() {
                    it.skip_current_dir();
                }
                continue;
            }
            if entry.path().symlink_metadata().is_err() {
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            paths.push(entry_path.to_path_buf());
        }
        paths
    })
    .await?;
    for zip_path in zip_paths.into_iter() {
        let filename = match zip_path.strip_prefix(dir).ok().and_then(|v| v.to_str()) {
            Some(v) => v,
            None => continue,
        };
        let entry_options =
            EntryOptions::new(filename.to_owned(), Compression::Deflate).unix_permissions(0o644);
        let mut file = File::open(&zip_path).await?;
        let mut file_writer = writer.write_entry_stream(entry_options).await?;
        io::copy(&mut file, &mut file_writer).await?;
        file_writer.close().await?;
    }
    writer.close().await?;
    Ok(())
}

fn extract_cache_headers(meta: &Metadata) -> Option<(ETag, LastModified)> {
    let mtime = meta.modified().ok()?;
    let timestamp = to_timestamp(&mtime);
    let size = meta.len();
    let etag = format!(r#""{}-{}""#, timestamp, size)
        .parse::<ETag>()
        .unwrap();
    let last_modified = LastModified::from(mtime);
    Some((etag, last_modified))
}

#[derive(Debug)]
struct RangeValue {
    start: u64,
    end: Option<u64>,
}

fn parse_range(headers: &HeaderMap<HeaderValue>) -> Option<RangeValue> {
    let range_hdr = headers.get(RANGE)?;
    let hdr = range_hdr.to_str().ok()?;
    let mut sp = hdr.splitn(2, '=');
    let units = sp.next().unwrap();
    if units == "bytes" {
        let range = sp.next()?;
        let mut sp_range = range.splitn(2, '-');
        let start: u64 = sp_range.next().unwrap().parse().ok()?;
        let end: Option<u64> = if let Some(end) = sp_range.next() {
            if end.is_empty() {
                None
            } else {
                Some(end.parse().ok()?)
            }
        } else {
            None
        };
        Some(RangeValue { start, end })
    } else {
        None
    }
}

fn status_forbid(res: &mut Response) {
    *res.status_mut() = StatusCode::FORBIDDEN;
    *res.body_mut() = Body::from("Forbidden");
}

fn status_not_found(res: &mut Response) {
    *res.status_mut() = StatusCode::NOT_FOUND;
    *res.body_mut() = Body::from("Not Found");
}

fn status_no_content(res: &mut Response) {
    *res.status_mut() = StatusCode::NO_CONTENT;
}

fn is_hidden(hidden: &[String], file_name: &str) -> bool {
    hidden.iter().any(|v| glob(v, file_name))
}

fn set_webdav_headers(res: &mut Response) {
    res.headers_mut().insert(
        "Allow",
        HeaderValue::from_static("GET,HEAD,PUT,OPTIONS,DELETE,PROPFIND,COPY,MOVE"),
    );
    res.headers_mut()
        .insert("DAV", HeaderValue::from_static("1,2"));
}
