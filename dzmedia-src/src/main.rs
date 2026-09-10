#![allow(dead_code)]

use axum::{
    routing::{get, post},
    http::StatusCode,
    http::{HeaderMap, Method, header::{RANGE, CONTENT_RANGE, ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_TYPE}},
    response::{IntoResponse, Html},
    extract::{Json, State, Query, Form, Host},
    Router,
};
use tower_http::{cors::{CorsLayer, Any}, compression::CompressionLayer, trace::TraceLayer};
use serde_json::json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use bytes::Bytes;
use futures_util::StreamExt;
use axum::body::Body;
use axum::http::HeaderValue;
use blowfish::Blowfish;
use cipher::{KeyIvInit, BlockDecryptMut};
use cipher::block_padding::NoPadding;
use cbc::Decryptor;
use reqwest::{cookie::Jar, Url};
use reqwest::cookie::CookieStore;
use reqwest::header::ACCEPT;
use lofty::{
    config::WriteOptions,
    picture::{Picture, PictureType},
    tag::{Accessor, Tag, TagExt, TagType},
};
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{timeout, Duration};

type BoxErr = Box<dyn std::error::Error + Send + Sync + 'static>;

mod api;
use api::{APIClient, APIError, Format};

#[derive(Clone, Serialize, Deserialize)]
struct ArlSession {
    check_form: String,
    license_token: String,
}

#[derive(Clone)]
struct CdnCacheEntry {
    cdn_url: String,
    decrypt_id: u64,
    format: String,
    expires_at: std::time::Instant,
}

#[derive(Clone)]
struct AppState {
    api: Arc<Mutex<APIClient>>,
    api_by_arl: Arc<RwLock<HashMap<String, Arc<Mutex<APIClient>>>>>,
    arl_sessions: Arc<RwLock<HashMap<String, ArlSession>>>,
    pair: Arc<RwLock<HashMap<String, PairSession>>>,
    pair_store_path: String,
    arl_store_path: String,
    /// CDN URL кэш для предзагрузки. Ключ: track_id. TTL 20 мин.
    cdn_cache: Arc<RwLock<HashMap<u64, CdnCacheEntry>>>,
}

fn license_token_from_ud(ud: &serde_json::Value) -> String {
    ud.pointer("/USER/OPTIONS/license_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

async fn store_arl_session(state: &AppState, arl: &str, check_form: &str, license_token: &str) {
    if arl.len() < 20 {
        return;
    }
    let mut map = state.arl_sessions.write().await;
    if map.len() >= 64 {
        map.clear();
    }
    map.insert(
        arl.to_string(),
        ArlSession {
            check_form: check_form.to_string(),
            license_token: license_token.to_string(),
        },
    );
    arl_store_save(state).await;
}

async fn arl_store_save(state: &AppState) {
    let path = state.arl_store_path.trim();
    if path.is_empty() {
        return;
    }
    let map = state.arl_sessions.read().await.clone();
    let Ok(txt) = serde_json::to_string(&map) else { return };
    let tmp = format!("{path}.tmp");
    if tokio::fs::write(&tmp, txt).await.is_ok() {
        let _ = tokio::fs::rename(&tmp, path).await;
    }
}

async fn arl_store_load(state: &AppState) {
    let path = state.arl_store_path.trim();
    if path.is_empty() {
        return;
    }
    if let Ok(txt) = tokio::fs::read_to_string(path).await {
        if let Ok(map) = serde_json::from_str::<HashMap<String, ArlSession>>(&txt) {
            *state.arl_sessions.write().await = map;
        }
    }
}

fn json_error(status: StatusCode, message: impl Into<String>) -> axum::response::Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

async fn api_client_for_arl(state: &AppState, arl: Option<String>) -> Arc<Mutex<APIClient>> {
    let Some(arl) = arl.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        return state.api.clone();
    };

    let mut map = state.api_by_arl.write().await;
    if let Some(c) = map.get(&arl) {
        return c.clone();
    }
    if map.len() >= 32 {
        map.clear();
    }
    let session = state.arl_sessions.read().await.get(&arl).cloned();
    let client = if let Some(s) = session {
        APIClient::new_with_arl_session(arl.clone(), s.check_form, s.license_token)
    } else {
        APIClient::new_with_arl(arl.clone())
    };
    let c = Arc::new(Mutex::new(client));
    map.insert(arl, c.clone());
    c
}

fn extract_media_url_and_format(json: &serde_json::Value, formats: &Vec<&str>) -> (String, String, usize) {
    use std::io::Write;
    let mut log_file = std::fs::OpenOptions::new().create(true).append(true).open("debug_dzmedia.log").unwrap();
    let _ = writeln!(log_file, "--- MEDIA JSON RESPONSE ---");
    let _ = writeln!(log_file, "{}", serde_json::to_string_pretty(json).unwrap_or_default());

    let data = json.get("data").and_then(|v| v.as_array());
    let Some(data_arr) = data else {
        return (String::new(), String::new(), 0);
    };

    for f_str in formats {
        for (i, data_item) in data_arr.iter().enumerate() {
            if let Some(errs) = data_item.get("errors").and_then(|v| v.as_array()) {
                if !errs.is_empty() { continue; }
            }
            let media_arr = data_item.get("media").and_then(|v| v.as_array());
            let Some(media_arr) = media_arr else { continue; };
            for m in media_arr {
                let mut m_format = m.get("format").and_then(|v| v.as_str()).unwrap_or("");
                if m_format.is_empty() {
                    m_format = m.get("format_name").and_then(|v| v.as_str()).unwrap_or("");
                }
                
                let mut matched = false;
                if m_format.eq_ignore_ascii_case(*f_str) {
                    matched = true;
                } else if m_format.is_empty() {
                    if let Some(n) = m.get("format").and_then(|v| v.as_i64()) {
                        let n_str = match n {
                            9 => "FLAC",
                            3 => "MP3_320",
                            1 => "MP3_128",
                            _ => "",
                        };
                        if n_str.eq_ignore_ascii_case(*f_str) {
                            matched = true;
                            m_format = n_str;
                        }
                    }
                }

                if matched {
                    if let Some(sources) = m.get("sources").and_then(|v| v.as_array()) {
                        let mut preferred = Vec::new();
                        if let Some(s1) = sources.get(1).and_then(|s| s.get("url")).and_then(|u| u.as_str()) { preferred.push(s1); }
                        for s in sources {
                            if let Some(u) = s.get("url").and_then(|v| v.as_str()) {
                                if u.contains("dzcdn.net/media/") { preferred.push(u); }
                            }
                        }
                        if let Some(s0) = sources.get(0).and_then(|s| s.get("url")).and_then(|u| u.as_str()) { preferred.push(s0); }
                        for s in sources {
                            if let Some(u) = s.get("url").and_then(|v| v.as_str()) { preferred.push(u); }
                        }
                        for p in preferred {
                            let p = p.trim();
                            if !p.is_empty() {
                                return (p.to_string(), m_format.to_string(), i);
                            }
                        }
                    }
                }
            }
        }
    }

    for (i, data_item) in data_arr.iter().enumerate() {
        if let Some(errs) = data_item.get("errors").and_then(|v| v.as_array()) {
            if !errs.is_empty() { continue; }
        }
        let media_arr = data_item.get("media").and_then(|v| v.as_array());
        let Some(media_arr) = media_arr else { continue; };
        for m in media_arr {
            let mut m_format = m.get("format").and_then(|v| v.as_str()).unwrap_or("");
            if m_format.is_empty() {
                m_format = m.get("format_name").and_then(|v| v.as_str()).unwrap_or("");
            }
            if m_format.is_empty() {
                if let Some(n) = m.get("format").and_then(|v| v.as_i64()) {
                    m_format = match n {
                        9 => "FLAC",
                        3 => "MP3_320",
                        1 => "MP3_128",
                        _ => "",
                    };
                }
            }
            if let Some(sources) = m.get("sources").and_then(|v| v.as_array()) {
                for s in sources {
                    if let Some(u) = s.get("url").and_then(|v| v.as_str()) {
                        let p = u.trim();
                        if !p.is_empty() {
                            return (p.to_string(), m_format.to_string(), i);
                        }
                    }
                }
            }
        }
    }

    (String::new(), String::new(), 0)
}

fn total_from_content_range(v: &str) -> Option<u64> {
    let v = v.trim();
    let (_, rest) = v.split_once('/')?;
    if rest.trim() == "*" {
        return None;
    }
    rest.trim().parse::<u64>().ok()
}

fn media_response_err(json: &serde_json::Value) -> String {
    if let Some(errs) = json.get("errors").and_then(|v| v.as_array()) {
        if let Some(first) = errs.first() {
            let s = first.to_string();
            return s.chars().take(160).collect();
        }
    }
    json.to_string().chars().take(160).collect()
}

async fn fetch_media_url(
    client: &APIClient,
    formats: &[Format],
    track_tokens: Vec<&str>,
) -> Result<(String, String, usize), String> {
    if client.license_token.is_empty() {
        return Err("license_token empty".to_string());
    }

    let media_resp = client
        .get_media(&formats.to_vec(), track_tokens)
        .await
        .map_err(|e| e.to_string())?;

    let status = media_resp.status();
    let media_text = media_resp
        .text()
        .await
        .map_err(|_| "media:read".to_string())?;

    let media_json: serde_json::Value = serde_json::from_str(&media_text).map_err(|_| {
        let snip: String = media_text.chars().take(200).collect();
        format!("media_bad_json:{}:{}", status.as_u16(), snip)
    })?;

    let format_strings: Vec<String> = formats.iter().map(|f| format!("{:?}", f)).collect();
    let format_strs: Vec<&str> = format_strings.iter().map(|s| s.as_str()).collect();

    let (url, fmt, idx) = extract_media_url_and_format(&media_json, &format_strs);
    if !url.is_empty() {
        return Ok((url, fmt, idx));
    }

    Err(format!(
        "media:{}:{}",
        status.as_u16(),
        media_response_err(&media_json)
    ))
}

async fn resolve_fallback_id(client: &mut APIClient, id: u64) -> u64 {
    if client.license_token.is_empty() {
        let _ = client.force_renew().await;
    }
    let q_json = serde_json::json!({"sng_ids":[id],"array_default":["SNG_ID","FALLBACK"]});
    if let Ok(r) = client.api_call::<serde_json::Value, serde_json::Value>("song.getListData", &q_json).await {
        if let Some(item) = r.pointer("/data/0") {
            if let Some(fallback) = item.get("FALLBACK") {
                if let Some(fid) = fallback.get("SNG_ID").and_then(|v| {
                    if let Some(s) = v.as_str() { s.parse::<u64>().ok() }
                    else if let Some(n) = v.as_u64() { Some(n) }
                    else { None }
                }) {
                    if fid > 0 { return fid; }
                }
            }
        }
    }
    id
}

async fn media_url_for_track(
    client: &mut APIClient,
    id: u64,
    formats: &Vec<Format>,
) -> Result<(String, String, u64), String> {
    use std::io::Write;
    let mut log_file = std::fs::OpenOptions::new().create(true).append(true).open("debug_dzmedia.log").unwrap();
    let _ = writeln!(log_file, "--- NEW REQUEST FOR ID {} ---", id);

    if client.license_token.is_empty() {
        if let Err(e) = client.force_renew().await {
            let _ = writeln!(log_file, "force_renew err: {}", e);
            return Err(format!("renew:{e}"));
        }
    }

    let q_json = serde_json::json!({"sng_ids":[id],"array_default":["SNG_ID","TRACK_TOKEN","FALLBACK","AVAILABLE_COUNTRIES"]});
    let r: serde_json::Value = client.api_call("song.getListData", &q_json).await.map_err(|e| {
        let _ = writeln!(log_file, "api_call err: {}", e);
        e.to_string()
    })?;

    let item = r.pointer("/data/0").ok_or_else(|| {
        let _ = writeln!(log_file, "No valid ID");
        "No valid ID".to_string()
    })?;

    let track_token = item.get("TRACK_TOKEN").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let fallback = item.get("FALLBACK");
    let fallback_token = fallback.and_then(|f| f.get("TRACK_TOKEN")).and_then(|v| v.as_str()).unwrap_or("").to_string();

    let fallback_id = fallback.and_then(|f| {
        f.get("SNG_ID").and_then(|v| {
            if let Some(s) = v.as_str() { s.parse::<u64>().ok() }
            else if let Some(n) = v.as_u64() { Some(n) }
            else { None }
        })
    }).unwrap_or(0);

    // AVAILABLE_COUNTRIES обычно вида {"stream": ["FR","NL",...], ...} — список
    // ISO-кодов стран, где у трека есть права на конкретное действие (право
    // "stream" — то самое, от которого зависит media.getUrl). Если сюда не
    // входит страна, откуда идёт запрос — media.getUrl молча вернёт пустой
    // media, что бы мы ни делали. Значение пишем в лог как есть, включая
    // fallback-варианты ниже, чтобы не гадать, а сразу увидеть список стран.
    let _ = writeln!(
        log_file,
        "track_token: {}, fallback_id: {}, fallback_token: {}, available_countries: {}",
        track_token,
        fallback_id,
        fallback_token,
        item.get("AVAILABLE_COUNTRIES").map(|v| v.to_string()).unwrap_or_else(|| "<нет поля>".to_string())
    );

    if fallback_id > 0 {
        let q_fb = serde_json::json!({"sng_ids":[fallback_id],"array_default":["SNG_ID","TRACK_TOKEN","FALLBACK","AVAILABLE_COUNTRIES"]});
        let _ = writeln!(log_file, "Querying fallback ID: {}", fallback_id);
        if let Ok(r_fb) = client.api_call::<serde_json::Value, serde_json::Value>("song.getListData", &q_fb).await {
            if let Some(item_fb) = r_fb.pointer("/data/0") {
                let _ = writeln!(
                    log_file,
                    "fallback available_countries: {}",
                    item_fb.get("AVAILABLE_COUNTRIES").map(|v| v.to_string()).unwrap_or_else(|| "<нет поля>".to_string())
                );
                if let Some(real_tk) = item_fb.get("TRACK_TOKEN").and_then(|v| v.as_str()) {
                    let _ = writeln!(log_file, "Fetched real_tk for fallback: {}", real_tk);
                    let tokens = vec![real_tk];
                    match fetch_media_url(client, formats, tokens).await {
                        Ok((url, fmt, _)) => {
                            let _ = writeln!(log_file, "fetch_media_url SUCCESS for fallback: fmt={}", fmt);
                            return Ok((url, fmt, fallback_id));
                        },
                        Err(e) => {
                            let _ = writeln!(log_file, "fetch_media_url FAILED for fallback: {}", e);
                        }
                    }
                } else {
                    let _ = writeln!(log_file, "NO TRACK_TOKEN in fallback response");
                }
            } else {
                let _ = writeln!(log_file, "Empty data array in fallback response");
            }
        } else {
            let _ = writeln!(log_file, "api_call for fallback ID FAILED");
        }
    }

    let mut tokens = Vec::new();
    let mut token_ids = Vec::new();
    if !track_token.is_empty() {
        tokens.push(track_token.as_str());
        token_ids.push(id);
    }
    if !fallback_token.is_empty() {
        tokens.push(fallback_token.as_str());
        let fid = if fallback_id > 0 { fallback_id } else { id };
        token_ids.push(fid);
    }

    if tokens.is_empty() {
        let _ = writeln!(log_file, "empty TRACK_TOKEN and FALLBACK");
        return Err("empty TRACK_TOKEN and FALLBACK".to_string());
    }

    let _ = writeln!(log_file, "Falling back to old logic. Tokens: {:?}", tokens);
    let res = fetch_media_url(client, formats, tokens).await;
    match res {
        Ok((url, fmt, idx)) => {
            let _ = writeln!(log_file, "Old logic SUCCESS: fmt={}", fmt);
            let id_to_use = *token_ids.get(idx).unwrap_or(&id);
            Ok((url, fmt, id_to_use))
        },
        Err(e) => {
            let _ = writeln!(log_file, "Old logic FAILED: {}", e);
            Err(e)
        }
    }
}

fn upstream_bases() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    let env = std::env::var("DZMEDIA_UPSTREAM").ok().unwrap_or_default();
    let env = env.trim();
    if env == "-" {
        return out;
    }

    if !env.is_empty() {
        for part in env.split(',') {
            let s = part.trim();
            if s.is_empty() {
                continue;
            }
            out.push(s.trim_end_matches('/').to_string());
        }
    }

    out
}
fn upstream_get_url_endpoint(base: &str) -> String {
    let b = base.trim_end_matches('/');
    if b.ends_with("/get_url") {
        b.to_string()
    } else {
        format!("{b}/get_url")
    }
}

async fn upstream_get_url_text(formats: &Vec<Format>, ids: &Vec<u64>) -> Result<String, String> {
    let bases = upstream_bases();
    if bases.is_empty() {
        return Err("upstream:disabled".to_string());
    }

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|_| "upstream:client".to_string())?;

    let mut last_err = String::new();
    for base in bases {
        let url = upstream_get_url_endpoint(&base);
        let r = match client
            .post(url)
            .json(&json!({ "formats": formats, "ids": ids }))
            .send()
            .await
        {
            Ok(v) => v,
            Err(e) => {
                last_err = format!("upstream:network:{base}:{e}");
                continue;
            }
        };

        let status = r.status();
        let text = match r.text().await {
            Ok(v) => v,
            Err(e) => {
                last_err = format!("upstream:read:{base}:{e}");
                continue;
            }
        };

        if !status.is_success() {
            let snip: String = text.chars().take(200).collect();
            last_err = format!("upstream:{}:{base}:{snip}", status.as_u16());
            continue;
        }

        return Ok(text);
    }

    Err(if last_err.is_empty() {
        "upstream:failed".to_string()
    } else {
        last_err
    })
}

async fn upstream_media_url(id: u64, formats: &Vec<Format>) -> Result<String, String> {
    let text = upstream_get_url_text(formats, &vec![id]).await?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| "upstream:parse".to_string())?;
    let format_strings: Vec<String> = formats.iter().map(|f| format!("{:?}", f)).collect();
    let format_strs: Vec<&str> = format_strings.iter().map(|s| s.as_str()).collect();
    let (url, _, _) = extract_media_url_and_format(&v, &format_strs);
    if url.is_empty() {
        return Err("upstream:no_url".to_string());
    }
    Ok(url)
}

async fn public_track_duration(id: u64) -> Option<u32> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;
    let r = client
        .get(format!("https://api.deezer.com/track/{id}"))
        .send()
        .await
        .ok()?;
    if !r.status().is_success() {
        return None;
    }
    let v: serde_json::Value = r.json().await.ok()?;
    v.get("duration").and_then(|d| d.as_u64()).map(|d| d as u32)
}

#[derive(Deserialize)]
struct DeezerTrackList {
    data: Vec<DeezerTrack>
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct DeezerTrack {
    TRACK_TOKEN: Option<String>,
    FALLBACK: Option<DeezerTrackFallback>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct DeezerTrackFallback {
    TRACK_TOKEN: Option<String>,
    SNG_ID: Option<String>,
}

async fn root() -> &'static str {
    "marecchione gay af (v2.1)"
}

/// /debug_log — отдаёт хвост debug_dzmedia.log (пишется в media_url_for_track
/// на каждый запрос: TRACK_TOKEN, fallback_id, реальная ошибка api_call и
/// т.д.) — чтобы не лезть в шелл контейнера, просто открыть в браузере.
async fn debug_log() -> impl IntoResponse {
    match std::fs::read_to_string("debug_dzmedia.log") {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(400);
            let tail = lines[start..].join("\n");
            (StatusCode::OK, tail).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, format!("лога ещё нет: {e}")).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct RequestParams {
    formats: Vec<Format>,
    ids: Vec<u64>,
    arl: Option<String>,
}

async fn get_url(State(state): State<AppState>, Json(req): Json<RequestParams>) -> impl IntoResponse {
    if req.formats.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "Format list cannot be empty");
    }
    if req.ids.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "ID list cannot be empty");
    }

    let arl = req.arl.clone().unwrap_or_default().trim().to_string();
    if arl.is_empty() {
        if let Ok(t) = upstream_get_url_text(&req.formats, &req.ids).await {
            return (StatusCode::OK, t).into_response();
        }
    }

    let client = api_client_for_arl(&state, req.arl.clone()).await;
    let media_resp = {
        let mut client = client.lock().await;
        let resp: Result<DeezerTrackList, APIError> = client
            .api_call(
                "song.getListData",
                &json!({"sng_ids":req.ids,"array_default":["SNG_ID","TRACK_TOKEN","FALLBACK"]}),
            )
            .await;
        let track_list = match resp {
            Ok(t) => t,
            Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
        };

        if track_list.data.is_empty() {
            return json_error(StatusCode::BAD_REQUEST, "No valid IDs found");
        }

        let mut track_tokens: Vec<String> = Vec::new();
        for t in &track_list.data {
            if let Some(ref tk) = t.TRACK_TOKEN {
                if !tk.is_empty() {
                    track_tokens.push(tk.clone());
                }
            }
            if let Some(ref fb) = t.FALLBACK {
                if let Some(ref tk) = fb.TRACK_TOKEN {
                    if !tk.is_empty() {
                        track_tokens.push(tk.clone());
                    }
                }
            }
        }

        if track_tokens.is_empty() {
            return json_error(StatusCode::BAD_REQUEST, "No tokens found in list data");
        }

        let track_tokens_refs: Vec<&str> = track_tokens.iter().map(|s| s.as_str()).collect();

        match client.get_media(&req.formats, track_tokens_refs).await {
            Ok(r) => r,
            Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
        }
    };

    match media_resp.text().await {
        Ok(t) => (StatusCode::OK, t).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct FetchParams {
    url: String,
}

async fn fetch(Query(q): Query<FetchParams>) -> impl IntoResponse {
    let parsed = match q.url.parse::<Url>() {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid url".to_string()).into_response(),
    };

    let host = parsed.host_str().unwrap_or("");
    if !(host.ends_with(".dzcdn.net")) {
        return (StatusCode::FORBIDDEN, "Host not allowed".to_string()).into_response();
    }

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap();

    let resp = match client.get(parsed).send().await {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Upstream request failed".to_string()).into_response(),
    };

    let status = resp.status();
    if !status.is_success() {
        return (StatusCode::BAD_GATEWAY, format!("Upstream status: {}", status)).into_response();
    }

    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Upstream read failed".to_string()).into_response(),
    };

    (
        StatusCode::OK,
        [(CONTENT_TYPE, "audio/mpeg")],
        Bytes::from(bytes),
    )
        .into_response()
}

const SECRET: &str = "g4el58wc0zvf9na1";

fn blowfish_key(track_id: u64) -> [u8; 16] {
    let md5hex = format!("{:x}", md5::compute(track_id.to_string().as_bytes()));
    let md5hex = md5hex.as_bytes();
    let secret = SECRET.as_bytes();
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = md5hex[i] ^ md5hex[i + 16] ^ secret[i];
    }
    out
}

/// Синхронная (CPU-bound) расшифровка блочного blowfish-шифра. Вынесена в
/// отдельную функцию, чтобы вызывать её через tokio::task::spawn_blocking —
/// иначе на слабом контейнере (0.25 vCPU) расшифровка крупного FLAC блокирует
/// единственный воркер-поток раннера на секунды, и в это время сервис не
/// отвечает вообще ни на что, включая health-check от прокси (отсюда 502
/// "Host: Error" при живом и не упавшем процессе).
fn decrypt_track_sync(enc: &[u8], decrypt_id: u64) -> Vec<u8> {
    let key = blowfish_key(decrypt_id);
    let mut dec = enc.to_vec();
    let block_size = 2048usize;
    let mut bi = 0usize;
    let mut pos = 0usize;
    while pos + block_size <= dec.len() {
        if bi % 3 == 0 {
            let _ = decrypt_stripe(&mut dec[pos..pos + block_size], &key);
        }
        bi += 1;
        pos += block_size;
    }
    dec
}

fn decrypt_stripe(block: &mut [u8], key: &[u8; 16]) -> Result<(), ()> {
    let iv = [0u8, 1, 2, 3, 4, 5, 6, 7];
    let dec = Decryptor::<Blowfish>::new_from_slices(key, &iv).map_err(|_| ())?;
    dec.decrypt_padded_mut::<NoPadding>(block).map_err(|_| ())?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct StreamParams {
    id: u64,
    format: Option<String>,
    arl: Option<String>,
    title: Option<String>,
    performer: Option<String>,
    duration: Option<u64>,
    album: Option<String>,
    cover_url: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct AudioTagMeta {
    title: Option<String>,
    performer: Option<String>,
    album: Option<String>,
    cover_url: Option<String>,
}

fn normalized_opt(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

impl From<&StreamParams> for AudioTagMeta {
    fn from(params: &StreamParams) -> Self {
        Self {
            title: normalized_opt(&params.title),
            performer: normalized_opt(&params.performer),
            album: normalized_opt(&params.album),
            cover_url: normalized_opt(&params.cover_url),
        }
    }
}

async fn stream_info(State(state): State<AppState>, Query(q): Query<StreamParams>) -> impl IntoResponse {
    let _ = std::fs::remove_file("debug_dzmedia.log");
    let formats = match q.format.as_deref().unwrap_or("AUTO") {
        "FLAC"     => vec![Format::FLAC, Format::MP3_320, Format::MP3_128],
        "MP3_320"  => vec![Format::MP3_320, Format::MP3_128],
        "MP3_MISC" => vec![Format::MP3_MISC, Format::MP3_128],
        "MP3_128"  => vec![Format::MP3_128],
        _          => vec![Format::FLAC, Format::MP3_320, Format::MP3_128],
    };

    let requested = q.format.clone().unwrap_or_else(|| "AUTO".to_string());
    let mut url: String  = String::new();
    let mut used: String = String::new();
    let mut last_err: Option<String> = None;

    let client = api_client_for_arl(&state, q.arl.clone()).await;
    let target_id = {
        let mut c = client.lock().await;
        resolve_fallback_id(&mut c, q.id).await
    };

    // Upstream (опционально — если DZMEDIA_UPSTREAM задан)
    if let Ok(text) = upstream_get_url_text(&formats, &vec![target_id]).await {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            let format_strings: Vec<String> = formats.iter().map(|f| format!("{:?}", f)).collect();
            let format_strs: Vec<&str> = format_strings.iter().map(|s| s.as_str()).collect();
            let (u, f, _) = extract_media_url_and_format(&v, &format_strs);
            url  = u;
            used = f;
        }
    }

    // ARL путь — до 2 попыток
    if url.is_empty() {
        if let Some(arl) = q.arl.clone().filter(|s| !s.trim().is_empty()) {
            'arl: for attempt in 0..2u8 {
                if attempt == 1 {
                    state.api_by_arl.write().await.remove(&arl);
                }
                let client = api_client_for_arl(&state, Some(arl.clone())).await;
                let res = {
                    let mut c = client.lock().await;
                    media_url_for_track(&mut c, q.id, &formats).await
                };
                match res {
                    Ok((u, f, _)) => { url = u; used = f; break 'arl; }
                    Err(e)     => { last_err = Some(e); }
                }
            }
        }
    }

    if url.is_empty() {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            last_err.unwrap_or_else(|| "stream_info:no_url".to_string()),
        );
    }

    let duration = public_track_duration(q.id).await.unwrap_or(0);
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();
    let r = http
        .get(url.clone())
        .header(reqwest::header::RANGE, "bytes=0-0")
        .send()
        .await;

    let mut total_bytes: u64 = 0;
    let mut mime: String = String::new();
    if let Ok(r) = r {
        if let Some(ct) = r.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
            mime = ct.to_string();
        }
        if let Some(cr) = r.headers().get(reqwest::header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .and_then(total_from_content_range)
        {
            total_bytes = cr;
        } else if let Some(cl) = r.headers().get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
        {
            total_bytes = cl.parse::<u64>().unwrap_or(0);
        }
    }

    let bitrate_kbps = if duration > 0 && total_bytes > 0 {
        ((total_bytes as f64) * 8.0 / (duration as f64) / 1000.0).round() as u64
    } else { 0 };

    let log_data = std::fs::read_to_string("debug_dzmedia.log").unwrap_or_default();

    (StatusCode::OK, Json(json!({
        "id":          q.id,
        "requested":   requested,
        "used":        used,
        "duration":    duration,
        "bytes":       total_bytes,
        "bitrate_kbps": bitrate_kbps,
        "mime":        mime,
        "log":         log_data
    }))).into_response()
}

/// /send_audio — HuggingFace скачивает трек и сам загружает его в Telegram через multipart.
/// Render к аудио не прикасается, только получает обратно file_id для кэша.
/// Требует: BOT_TOKEN env var на HuggingFace Space.
#[derive(Debug, Deserialize)]
struct SendAudioParams {
    id: u64,
    format: Option<String>,
    arl: Option<String>,
    /// Telegram chat_id куда отправить аудио
    chat_id: String,
    /// Опциональные метаданные
    title: Option<String>,
    performer: Option<String>,
    duration: Option<u64>,
    album: Option<String>,
    cover_url: Option<String>,
    /// Если передан — вместо sendAudio (новое сообщение) пробуем сразу
    /// отредактировать ЭТО сообщение через editMessageMedia, чтобы в чате
    /// не мелькало лишнее сообщение перед подменой на трек.
    message_id: Option<i64>,
}

impl From<&SendAudioParams> for AudioTagMeta {
    fn from(params: &SendAudioParams) -> Self {
        Self {
            title: normalized_opt(&params.title),
            performer: normalized_opt(&params.performer),
            album: normalized_opt(&params.album),
            cover_url: normalized_opt(&params.cover_url),
        }
    }
}

async fn fetch_cover_picture(cover_url: &str) -> Option<Picture> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .ok()?;
    let resp = http.get(cover_url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let bytes = resp.bytes().await.ok()?;
    let mut picture = Picture::from_reader(&mut Cursor::new(bytes.to_vec())).ok()?;
    picture.set_pic_type(PictureType::CoverFront);
    Some(picture)
}

/// Строит имя файла вида "Исполнитель - Название.ext" из метаданных трека,
/// с фоллбэком на "track_{id}.{ext}", если метаданных нет. Общая логика для
/// /download и /send_audio — раньше send_audio использовал только id, из-за
/// чего в Telegram трек отображался как "track_123456.flac" вместо названия.
fn build_track_filename(id: u64, ext: &str, meta: &AudioTagMeta) -> String {
    let safe = |s: &str, limit: usize| {
        s.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_")
            .chars()
            .take(limit)
            .collect::<String>()
    };

    match (meta.title.as_deref(), meta.performer.as_deref()) {
        (Some(title), Some(performer)) if !title.is_empty() && !performer.is_empty() => {
            format!("{} - {}.{}", safe(performer, 50), safe(title, 100), ext)
        }
        (Some(title), _) if !title.is_empty() => {
            format!("{}.{}", safe(title, 100), ext)
        }
        _ => format!("track_{}.{}", id, ext),
    }
}

/// Синхронная часть тегирования (временный файл + lofty save) — уносится в
/// spawn_blocking отдельно от inject_audio_metadata, чтобы не блокировать
/// раннер (см. decrypt_track_sync выше — та же причина).
fn tag_bytes_sync(
    bytes: Vec<u8>,
    ext: &str,
    title: Option<String>,
    performer: Option<String>,
    album: Option<String>,
    cover: Option<Picture>,
) -> Vec<u8> {
    let tag_type = if ext.eq_ignore_ascii_case("flac") {
        TagType::VorbisComments
    } else {
        TagType::Id3v2
    };

    let mut tag = Tag::new(tag_type);
    if let Some(title) = title {
        tag.set_title(title);
    }
    if let Some(performer) = performer {
        tag.set_artist(performer);
    }
    if let Some(album) = album {
        tag.set_album(album);
    }
    if let Some(picture) = cover {
        tag.push_picture(picture);
    }

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp_path = std::env::temp_dir().join(format!("dzmedia_tagged_{}.{}", unique, ext));
    if let Err(e) = std::fs::write(&temp_path, &bytes) {
        tracing::warn!("metadata temp write failed: {}", e);
        return bytes;
    }

    let write_options = if ext.eq_ignore_ascii_case("mp3") {
        WriteOptions::new().use_id3v23(true)
    } else {
        WriteOptions::new()
    };

    let write_result = tag.save_to_path(&temp_path, write_options);
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&temp_path);
        tracing::warn!("metadata tagging failed: {}", e);
        return bytes;
    }

    let tagged = match std::fs::read(&temp_path) {
        Ok(tagged) => tagged,
        Err(e) => {
            tracing::warn!("metadata temp read failed: {}", e);
            bytes
        }
    };
    let _ = std::fs::remove_file(&temp_path);
    tagged
}

async fn inject_audio_metadata(bytes: Vec<u8>, ext: &str, meta: &AudioTagMeta) -> Vec<u8> {
    let has_text = meta.title.is_some() || meta.performer.is_some() || meta.album.is_some();
    let cover = match meta.cover_url.as_deref() {
        Some(url) => fetch_cover_picture(url).await,
        None => None,
    };

    if !has_text && cover.is_none() {
        return bytes;
    }

    let ext_owned = ext.to_string();
    let title = meta.title.clone();
    let performer = meta.performer.clone();
    let album = meta.album.clone();
    // Клонируем как страховку: если поток запаникует, JoinError не отдаёт
    // обратно moved bytes — а мы обязаны вернуть хоть что-то воспроизводимое.
    let fallback = bytes.clone();

    match tokio::task::spawn_blocking(move || {
        tag_bytes_sync(bytes, &ext_owned, title, performer, album, cover)
    })
    .await
    {
        Ok(tagged) => tagged,
        Err(e) => {
            tracing::warn!("metadata tagging task panicked: {}", e);
            fallback
        }
    }
}

/// Пытается заменить существующее сообщение (например "Загружаю...",
/// созданное ботом заранее) треком через editMessageMedia — вместо того,
/// чтобы слать трек отдельным sendAudio и заставлять бота потом удалять
/// лишнее промежуточное сообщение. Используется, только если в запросе
/// передан message_id (см. SendAudioParams). При неудаче возвращает Err —
/// вызывающий код должен откатиться на обычный sendAudio.
// Единственная попытка editMessageMedia. Ошибки вида "message to edit not
// found" / "MESSAGE_ID_INVALID" ретраить бессмысленно — помечаем их как
// финальные через префикс "final:", чтобы внешний цикл не жёг на них попытки.
async fn try_edit_message_media_once(
    tg_http: &reqwest::Client,
    bot_token: &str,
    q: &SendAudioParams,
    message_id: i64,
    dec: &[u8],
    filename: &str,
    mime: &str,
) -> Result<String, String> {
    let tg_url = format!("https://api.telegram.org/bot{}/editMessageMedia", bot_token);

    // "media" — JSON-объект InputMediaAudio, файл ссылается на часть
    // multipart-формы через attach://<имя_части> (см. .part(...) ниже).
    let mut media = json!({
        "type": "audio",
        "media": "attach://audio_file",
    });
    if let Some(ref t) = q.title { media["title"] = json!(t); }
    if let Some(ref p) = q.performer { media["performer"] = json!(p); }
    if let Some(d) = q.duration { media["duration"] = json!(d); }

    let part = reqwest::multipart::Part::bytes(dec.to_vec())
        .file_name(filename.to_string())
        .mime_str(mime)
        .map_err(|e| format!("final:mime: {}", e))?;

    let form = reqwest::multipart::Form::new()
        .text("chat_id", q.chat_id.clone())
        .text("message_id", message_id.to_string())
        .text("media", media.to_string())
        .part("audio_file", part);

    let resp = tg_http
        .post(&tg_url)
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("upload: {}", e))?; // сетевая/таймаут ошибка — ретраим
    let status = resp.status();
    let j: serde_json::Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;

    if status.is_success() && j.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        let file_id = j
            .pointer("/result/audio/file_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if file_id.is_empty() {
            return Err("final:editMessageMedia: no file_id in response".to_string());
        }
        Ok(file_id)
    } else {
        let desc = j.get("description").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        // Такие ошибки не лечатся повтором — сообщение реально нельзя
        // отредактировать (устарело/удалено/чужое).
        let is_permanent = desc.contains("message to edit not found")
            || desc.contains("MESSAGE_ID_INVALID")
            || desc.contains("message can't be edited")
            || status.as_u16() == 400;
        let tag = if is_permanent { "final:" } else { "" };
        Err(format!("{}Telegram editMessageMedia {}: {}", tag, status, desc))
    }
}

// Ретраит editMessageMedia до 3 раз (сеть/таймаут на аплоад к Telegram —
// частая причина единичного сбоя на бесплатном хостинге), не откатываясь
// на sendAudio раньше времени. Если ошибка помечена как "final:" (сообщение
// реально нельзя отредактировать) — выходит сразу, без лишних попыток.
async fn try_edit_message_media(
    tg_http: &reqwest::Client,
    bot_token: &str,
    q: &SendAudioParams,
    message_id: i64,
    dec: &[u8],
    filename: &str,
    mime: &str,
) -> Result<String, String> {
    // 2 попытки, не 3 — у нас ограниченный бюджет времени (бот на своей
    // стороне отменяет весь запрос через DEEZER_SEND_AUDIO_TIMEOUT_MS,
    // по умолчанию 60с), и часть этого бюджета уже ушла на скачивание с CDN
    // и расшифровку до этой точки.
    let mut last_err = String::new();
    for attempt in 1..=2u8 {
        match try_edit_message_media_once(tg_http, bot_token, q, message_id, dec, filename, mime).await {
            Ok(file_id) => return Ok(file_id),
            Err(e) => {
                tracing::warn!("editMessageMedia attempt {} failed for track {}: {}", attempt, q.id, e);
                if let Some(stripped) = e.strip_prefix("final:") {
                    return Err(stripped.to_string());
                }
                last_err = e;
                if attempt < 2 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    Err(last_err)
}

async fn send_audio(
    State(state): State<AppState>,
    Query(q): Query<SendAudioParams>,
) -> impl IntoResponse {
    let bot_token = match std::env::var("BOT_TOKEN").ok().filter(|s| !s.is_empty()) {
        Some(t) => t,
        None => return json_error(StatusCode::SERVICE_UNAVAILABLE, "BOT_TOKEN not configured"),
    };

    let fmt_str = q.format.as_deref().unwrap_or("MP3_320");
    let formats = match fmt_str {
        "FLAC"     => vec![Format::FLAC, Format::MP3_320, Format::MP3_128],
        "MP3_320"  => vec![Format::MP3_320, Format::MP3_128],
        "MP3_128"  => vec![Format::MP3_128],
        _          => vec![Format::FLAC, Format::MP3_320, Format::MP3_128],
    };

    let arl_key = q.arl.as_ref().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        .or_else(|| std::env::var("DEEZER_ARL").ok().filter(|s| !s.is_empty()));
    if arl_key.is_none() {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "arl required");
    }

    // Resolve FALLBACK_ID
    let client = api_client_for_arl(&state, arl_key.clone()).await;
    let target_id = {
        let mut c = client.lock().await;
        resolve_fallback_id(&mut c, q.id).await
    };
    let mut decrypt_id = target_id;

    let mut cdn_url_opt: Option<String> = None;
    let mut used_fmt = String::new();
    let mut last_err: Option<String> = None;

    // Try upstream first
    if let Ok(text) = upstream_get_url_text(&formats, &vec![target_id]).await {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            let fstrs: Vec<String> = formats.iter().map(|f| format!("{:?}", f)).collect();
            let fstrs_ref: Vec<&str> = fstrs.iter().map(|s| s.as_str()).collect();
            let (u, f, _) = extract_media_url_and_format(&v, &fstrs_ref);
            if !u.is_empty() { cdn_url_opt = Some(u); used_fmt = f; }
        }
    }

    // Fallback: ARL
    for attempt in 0..2u8 {
        if cdn_url_opt.is_some() { break; }
        if attempt >= 1 {
            if let Some(ref arl) = arl_key { state.api_by_arl.write().await.remove(arl); }
        }
        let client = api_client_for_arl(&state, arl_key.clone()).await;
        let res = {
            let mut c = client.lock().await;
            if attempt >= 1 {
                if let Err(e) = c.force_renew().await { last_err = Some(format!("renew:{}", e)); continue; }
            }
            match timeout(Duration::from_secs(15), media_url_for_track(&mut c, target_id, &formats)).await {
                Ok(v) => v,
                Err(_) => Err("timeout".to_string()),
            }
        };
        match res {
            Ok((u, f, id_used)) => { cdn_url_opt = Some(u); used_fmt = f; decrypt_id = id_used; break; }
            Err(e) => { last_err = Some(e); }
        }
    }

    let cdn_url = match cdn_url_opt {
        Some(u) => u,
        None => {
            let err = last_err.unwrap_or_else(|| "send_audio:no_url".to_string());
            tracing::error!("send_audio {} failed: {}", q.id, err);
            return json_error(StatusCode::NOT_FOUND, "track not found");
        }
    };

    // Скачиваем зашифрованный файл с CDN
    let http = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(120)).build().unwrap();
    let resp = match http.get(&cdn_url).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => return json_error(StatusCode::BAD_GATEWAY, format!("CDN {}", r.status())),
        Err(e) => return json_error(StatusCode::BAD_GATEWAY, format!("CDN fetch: {}", e)),
    };
    let content_type = resp.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("audio/mpeg")
        .to_string();
    let enc = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => return json_error(StatusCode::BAD_GATEWAY, format!("CDN read: {}", e)),
    };

    // Расшифровываем в отдельном блокирующем потоке — decrypt_track_sync это
    // чистый CPU-bound цикл, на нём нельзя держать async-воркер.
    let mut dec = match tokio::task::spawn_blocking(move || decrypt_track_sync(&enc, decrypt_id)).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("send_audio {} decrypt task panicked: {}", q.id, e);
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "decrypt failed");
        }
    };

    let ext = if used_fmt.contains("FLAC") || content_type.contains("flac") { "flac" } else { "mp3" };
    let meta = AudioTagMeta::from(&q);
    dec = inject_audio_metadata(dec, ext, &meta).await;
    let mime = if ext == "flac" { "audio/flac" } else { "audio/mpeg" };
    let filename = build_track_filename(q.id, ext, &meta);

    // Загружаем в Telegram через отдельный клиент. Таймаут держим таким,
    // чтобы 2 попытки editMessageMedia + 1с пауза между ними гарантированно
    // укладывались в DEEZER_SEND_AUDIO_TIMEOUT_MS на стороне бота (по
    // умолчанию 60с), с запасом на уже потраченное время на CDN+decrypt.
    let tg_http = reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(25))
        .tcp_keepalive(Duration::from_secs(20))
        .build()
        .unwrap();

    // Если передан message_id — сначала пробуем отредактировать ЭТО
    // сообщение напрямую (editMessageMedia), чтобы в чате не мелькало
    // отдельное сообщение перед подменой на трек. Если не получилось
    // (например message_id устарел/удалён) — падаем в старый sendAudio.
    if let Some(message_id) = q.message_id {
        match try_edit_message_media(&tg_http, &bot_token, &q, message_id, &dec, &filename, mime).await {
            Ok(file_id) => {
                tracing::info!("editMessageMedia success for track {} (message_id {})", q.id, message_id);
                return (StatusCode::OK, Json(json!({
                    "ok": true,
                    "file_id": file_id,
                    "edited": true,
                    "format": ext,
                }))).into_response();
            }
            Err(e) => {
                tracing::warn!("editMessageMedia failed for track {}, falling back to sendAudio: {}", q.id, e);
            }
        }
    }

    let tg_url = format!("https://api.telegram.org/bot{}/sendAudio", bot_token);

    let mut tg_json: Option<serde_json::Value> = None;
    let mut last_tg_err: Option<String> = None;

    for attempt in 1..=3u8 {
        tracing::info!("Telegram sendAudio attempt {} for track {} ({} bytes)", attempt, q.id, dec.len());
        
        let part = reqwest::multipart::Part::bytes(dec.clone())
            .file_name(filename.clone())
            .mime_str(mime)
            .unwrap();
        let mut form = reqwest::multipart::Form::new()
            .text("chat_id", q.chat_id.clone())
            .part("audio", part);
        if let Some(ref t) = q.title { form = form.text("title", t.clone()); }
        if let Some(ref p) = q.performer { form = form.text("performer", p.clone()); }
        if let Some(d) = q.duration { form = form.text("duration", d.to_string()); }

        match tg_http.post(&tg_url).multipart(form).send().await {
            Ok(resp) => {
                let status = resp.status();
                match resp.json::<serde_json::Value>().await {
                    Ok(j) => {
                        if status.is_success() && j.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                            tg_json = Some(j);
                            tracing::info!("Telegram sendAudio success on attempt {}", attempt);
                            break;
                        }
                        let desc = j
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        tracing::warn!("Telegram sendAudio attempt {} failed: status={} desc={}", attempt, status, desc);
                        last_tg_err = Some(format!("Telegram {}: {}", status, desc));
                    }
                    Err(e) => {
                        tracing::warn!("Telegram sendAudio attempt {} parse failed: {}", attempt, e);
                        last_tg_err = Some(format!("Telegram parse: {}", e));
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Telegram sendAudio attempt {} upload failed: {}", attempt, e);
                last_tg_err = Some(format!("Telegram upload: {}", e));
            }
        }

        if attempt < 3 {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    let tg_json = match tg_json {
        Some(j) => j,
        None => {
            let err = last_tg_err.unwrap_or_else(|| "Telegram upload failed".to_string());
            tracing::error!("Telegram sendAudio final failure: {}", err);
            return json_error(StatusCode::BAD_GATEWAY, err);
        }
    };

    let file_id = tg_json.pointer("/result/audio/file_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let message_id = tg_json.pointer("/result/message_id")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    (StatusCode::OK, Json(json!({
        "ok": true,
        "file_id": file_id,
        "message_id": message_id,
        "edited": false,
        "format": ext,
    }))).into_response()
}

/// /download — like /stream but downloads full track into memory and returns with Content-Length.
/// Telegram requires Content-Length for sendAudio by URL; this endpoint ensures it.
async fn download(
    State(state): State<AppState>,
    Query(q): Query<StreamParams>,
) -> impl IntoResponse {
    let formats = match q.format.as_deref().unwrap_or("AUTO") {
        "FLAC"     => vec![Format::FLAC, Format::MP3_320, Format::MP3_128],
        "MP3_320"  => vec![Format::MP3_320, Format::MP3_128],
        "MP3_MISC" => vec![Format::MP3_MISC, Format::MP3_128],
        "MP3_128"  => vec![Format::MP3_128],
        _          => vec![Format::FLAC, Format::MP3_320, Format::MP3_128],
    };

    let arl_key = q.arl.as_ref().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    if arl_key.is_none() {
        return (StatusCode::SERVICE_UNAVAILABLE, "arl required").into_response();
    }

    // Resolve correct FALLBACK_ID for decryption
    let client = api_client_for_arl(&state, arl_key.clone()).await;
    let target_id = {
        let mut c = client.lock().await;
        resolve_fallback_id(&mut c, q.id).await
    };
    let mut decrypt_id = target_id;

    let mut url: Option<String> = None;
    let mut used_fmt = String::new();
    let mut last_err: Option<String> = None;

    // Try DZMEDIA_UPSTREAM first for highest quality
    if url.is_none() {
        if let Ok(text) = upstream_get_url_text(&formats, &vec![target_id]).await {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                let format_strings: Vec<String> = formats.iter().map(|f| format!("{:?}", f)).collect();
                let format_strs: Vec<&str> = format_strings.iter().map(|s| s.as_str()).collect();
                let (u, f, _) = extract_media_url_and_format(&v, &format_strs);
                if !u.is_empty() {
                    url = Some(u);
                    used_fmt = f;
                }
            }
        }
    }

    // Fallback: ARL path
    for attempt in 0..2u8 {
        if url.is_some() { break; }
        if attempt >= 1 {
            if let Some(ref arl) = arl_key {
                state.api_by_arl.write().await.remove(arl);
            }
        }
        let client = api_client_for_arl(&state, arl_key.clone()).await;
        let res = {
            let mut c = client.lock().await;
            if attempt >= 1 {
                if let Err(e) = c.force_renew().await {
                    last_err = Some(format!("renew:{}", e));
                    continue;
                }
            }
            match timeout(Duration::from_secs(15), media_url_for_track(&mut c, target_id, &formats)).await {
                Ok(v) => v,
                Err(_) => Err("timeout".to_string()),
            }
        };
        match res {
            Ok((u, f, id_used)) => { url = Some(u); used_fmt = f; decrypt_id = id_used; break; }
            Err(e) => { last_err = Some(e); }
        }
    }

    let cdn_url = match url {
        Some(u) => u,
        None => {
            let err = last_err.unwrap_or_else(|| "download:no_url".to_string());
            tracing::error!("download {} failed: {}", q.id, err);
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    };

    // Download the full encrypted file
    let http = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(120)).build().unwrap();
    let resp = match http.get(&cdn_url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("download {} cdn fetch failed: {}", q.id, e);
            return (StatusCode::BAD_GATEWAY, "CDN fetch failed").into_response();
        }
    };
    if !resp.status().is_success() {
        return (StatusCode::BAD_GATEWAY, "CDN error").into_response();
    }
    let content_type = resp.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("audio/mpeg")
        .to_string();
    let enc_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("download {} cdn read failed: {}", q.id, e);
            return (StatusCode::BAD_GATEWAY, "CDN read failed").into_response();
        }
    };

    // Decrypt in a blocking thread — decrypt_track_sync is a pure CPU-bound loop,
    // must not run inline on the async worker.
    let mut dec = match tokio::task::spawn_blocking(move || decrypt_track_sync(&enc_bytes, decrypt_id)).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("download {} decrypt task panicked: {}", q.id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "decrypt failed").into_response();
        }
    };

    // Determine file extension
    // Проверяем магические байты для определения РЕАЛЬНОГО формата файла
    let is_flac = dec.len() > 4 && &dec[0..4] == b"fLaC";
    let is_mp3 = dec.len() > 3 && (
        (&dec[0..3] == b"ID3") || // ID3 tag
        (dec[0] == 0xFF && (dec[1] & 0xE0) == 0xE0) // MP3 sync word
    );
    
    let ext = if is_flac {
        "flac"
    } else if is_mp3 || used_fmt.contains("MP3") {
        "mp3"
    } else if used_fmt.contains("FLAC") {
        // Заявлен FLAC, но магических байтов нет - возможно битый файл
        tracing::warn!("Track {} claimed as FLAC but magic bytes not found, treating as mp3", q.id);
        "mp3"
    } else {
        "mp3"
    };
    
    tracing::info!("Download track {}: claimed_format={}, detected_ext={}, size={} bytes", 
        q.id, used_fmt, ext, dec.len());
    
    let meta = AudioTagMeta::from(&q);
    dec = inject_audio_metadata(dec, ext, &meta).await;

    let filename = build_track_filename(q.id, ext, &meta);
    
    let ct = if ext == "flac" { "audio/flac" } else { "audio/mpeg" };
    
    tracing::info!("Sending file: {} ({})", filename, ct);

    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", ct)
        .header("Content-Length", dec.len().to_string())
        .header("Content-Disposition", format!("inline; filename=\"{}\"", filename))
        .header("Accept-Ranges", "bytes")
        .header("Access-Control-Allow-Origin", "*")
        .header("Cache-Control", "public, max-age=31536000")
        .body(axum::body::Body::from(dec))
        .unwrap()
        .into_response()
}

/// /warm — прогревает CDN URL кэш для трека.
/// Render вызывает этот эндпоинт ПЕРЕД отправкой sendAudio,
/// чтобы к моменту Telegram-запроса кэш уже был горячим.
async fn warm(
    State(state): State<AppState>,
    Query(q): Query<StreamParams>,
) -> impl IntoResponse {
    let fmt_str = q.format.as_deref().unwrap_or("AUTO");
    let formats = match fmt_str {
        "FLAC"     => vec![Format::FLAC, Format::MP3_320, Format::MP3_128],
        "MP3_320"  => vec![Format::MP3_320, Format::MP3_128],
        "MP3_MISC" => vec![Format::MP3_MISC, Format::MP3_128],
        "MP3_128"  => vec![Format::MP3_128],
        _          => vec![Format::FLAC, Format::MP3_320, Format::MP3_128],
    };

    let arl_key = q.arl.clone()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("DEEZER_ARL").ok().filter(|s| !s.is_empty()));

    if arl_key.is_none() {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "arl required");
    }

    // Проверяем — может уже в кэше есть свежая запись
    {
        let cache = state.cdn_cache.read().await;
        if let Some(e) = cache.get(&q.id) {
            if e.expires_at > std::time::Instant::now() {
                tracing::debug!("warm {}: already cached", q.id);
                return (StatusCode::OK, Json(json!({ "ok": true, "cached": true }))).into_response();
            }
        }
    }

    // Resolve fallback_id
    let client = api_client_for_arl(&state, arl_key.clone()).await;
    let target_id = {
        let mut c = client.lock().await;
        resolve_fallback_id(&mut c, q.id).await
    };
    let mut decrypt_id = target_id;
    let mut url: Option<String> = None;

    // Try upstream first
    if let Ok(text) = upstream_get_url_text(&formats, &vec![target_id]).await {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            let fstrs: Vec<String> = formats.iter().map(|f| format!("{:?}", f)).collect();
            let fstrs_ref: Vec<&str> = fstrs.iter().map(|s| s.as_str()).collect();
            let (u, _, _) = extract_media_url_and_format(&v, &fstrs_ref);
            if !u.is_empty() { url = Some(u); }
        }
    }

    // Fallback: ARL
    for attempt in 0..2u8 {
        if url.is_some() { break; }
        if attempt >= 1 {
            if let Some(ref arl) = arl_key { state.api_by_arl.write().await.remove(arl); }
        }
        let client = api_client_for_arl(&state, arl_key.clone()).await;
        let res = {
            let mut c = client.lock().await;
            if attempt >= 1 {
                if let Err(_) = c.force_renew().await { continue; }
            }
            match timeout(Duration::from_secs(15), media_url_for_track(&mut c, target_id, &formats)).await {
                Ok(v) => v,
                Err(_) => Err("timeout".to_string()),
            }
        };
        if let Ok((u, _, id_used)) = res { url = Some(u); decrypt_id = id_used; break; }
    }

    match url {
        Some(u) => {
            let mut cache = state.cdn_cache.write().await;
            if cache.len() > 200 { cache.retain(|_, e| e.expires_at > std::time::Instant::now()); }
            cache.insert(q.id, CdnCacheEntry {
                cdn_url: u,
                decrypt_id,
                format: fmt_str.to_string(),
                expires_at: std::time::Instant::now() + Duration::from_secs(20 * 60),
            });
            tracing::info!("warm {}: cached OK", q.id);
            (StatusCode::OK, Json(json!({ "ok": true, "cached": false }))).into_response()
        }
        None => {
            tracing::error!("warm {}: failed to get CDN URL", q.id);
            json_error(StatusCode::NOT_FOUND, "track not found")
        }
    }
}

async fn stream(
    State(state): State<AppState>,
    Query(q): Query<StreamParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let formats = match q.format.as_deref().unwrap_or("AUTO") {
        "FLAC"     => vec![Format::FLAC, Format::MP3_320, Format::MP3_128],
        "MP3_320"  => vec![Format::MP3_320, Format::MP3_128],
        "MP3_MISC" => vec![Format::MP3_MISC, Format::MP3_128],
        "MP3_128"  => vec![Format::MP3_128],
        _          => vec![Format::FLAC, Format::MP3_320, Format::MP3_128],
    };

    let arl_key = q.arl.clone()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut url: Option<String> = None;
    let mut decrypt_id: u64 = q.id; // overwritten after resolve_fallback_id
    let mut last_err: Option<String> = None;

    if arl_key.is_none() {
        tracing::error!("stream {}: arl missing", q.id);
        return (StatusCode::SERVICE_UNAVAILABLE, "arl required").into_response();
    }

    // ── CDN кэш: если есть свежая запись — пропускаем все Deezer API вызовы ──
    {
        let cache = state.cdn_cache.read().await;
        if let Some(e) = cache.get(&q.id) {
            if e.expires_at > std::time::Instant::now() {
                tracing::debug!("stream {}: CDN cache hit ({})", q.id, e.format);
                url = Some(e.cdn_url.clone());
                decrypt_id = e.decrypt_id;
            }
        }
    }

    if url.is_none() {
        // Resolve fallback_id for proper decryption key
        let client = api_client_for_arl(&state, arl_key.clone()).await;
        let target_id = {
            let mut c = client.lock().await;
            resolve_fallback_id(&mut c, q.id).await
        };
        decrypt_id = target_id;

        // Try DZMEDIA_UPSTREAM first — gives highest available quality (FLAC/320)
        if url.is_none() {
            if let Ok(text) = upstream_get_url_text(&formats, &vec![target_id]).await {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    let format_strings: Vec<String> = formats.iter().map(|f| format!("{:?}", f)).collect();
                    let format_strs: Vec<&str> = format_strings.iter().map(|s| s.as_str()).collect();
                    let (u, _, _) = extract_media_url_and_format(&v, &format_strs);
                    if !u.is_empty() {
                        url = Some(u);
                    }
                }
            }
        }

        // Fallback: use ARL to get CDN URL via Deezer API
        for attempt in 0..2u8 {
            if url.is_some() { break; }
            if attempt >= 1 {
                if let Some(ref arl) = arl_key {
                    state.api_by_arl.write().await.remove(arl);
                } else {
                    *state.api.lock().await = APIClient::new();
                }
            }
            let client = api_client_for_arl(&state, arl_key.clone()).await;
            let res = {
                let mut c = client.lock().await;
                if attempt >= 1 {
                    if let Err(e) = c.force_renew().await {
                        last_err = Some(format!("renew:{}", e));
                        continue;
                    }
                }
                match timeout(Duration::from_secs(12), media_url_for_track(&mut c, target_id, &formats)).await {
                    Ok(v) => v,
                    Err(_) => Err("timeout".to_string()),
                }
            };
            match res {
                Ok((u, fmt, id_used)) => { url = Some(u); decrypt_id = id_used; let _ = fmt; break; }
                Err(e) => { last_err = Some(e); }
            }
        }

        // ── Пишем в кэш если удалось получить URL ──
        if let Some(ref u) = url {
            let mut cache = state.cdn_cache.write().await;
            if cache.len() > 200 {
                cache.retain(|_, e| e.expires_at > std::time::Instant::now());
            }
            cache.insert(q.id, CdnCacheEntry {
                cdn_url: u.clone(),
                decrypt_id,
                format: q.format.clone().unwrap_or_else(|| "AUTO".to_string()),
                expires_at: std::time::Instant::now() + Duration::from_secs(20 * 60),
            });
        }
    }

    let url = match url {
        Some(u) => u,
        None => {
            let err = last_err.unwrap_or_else(|| "stream:no_url".to_string());
            tracing::error!("stream {} failed: {}", q.id, err);
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    };


    fn parse_range_header(v: &str) -> Option<(u64, Option<u64>)> {
        let v = v.trim();
        let v = v.strip_prefix("bytes=")?;
        let mut it = v.splitn(2, '-');
        let a = it.next()?.trim();
        let b = it.next().unwrap_or("").trim();
        if a.is_empty() {
            return None;
        }
        let start = a.parse::<u64>().ok()?;
        let end = if b.is_empty() {
            None
        } else {
            let e = b.parse::<u64>().ok()?;
            Some(e)
        };
        Some((start, end))
    }

    fn parse_total_from_content_range(v: &str) -> Option<u64> {
        let v = v.trim();
        let (_, rest) = v.split_once('/')?;
        if rest.trim() == "*" {
            return None;
        }
        rest.trim().parse::<u64>().ok()
    }

    let req_range = headers
        .get(RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_range_header);

    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap();

    let block_size: u64 = 2048;
    let mut block_index: u64 = 0;
    let mut drop_bytes: usize = 0;
    let mut remaining: Option<u64> = None;

    let mut req = http.get(&url);
    if let Some((start, end)) = req_range {
        let aligned_start = start - (start % block_size);
        drop_bytes = (start - aligned_start) as usize;
        block_index = aligned_start / block_size;
        if let Some(e) = end {
            if e >= start {
                remaining = Some(e - start + 1);
            }
            req = req.header(reqwest::header::RANGE, format!("bytes={}-{}", aligned_start, e));
        } else {
            req = req.header(reqwest::header::RANGE, format!("bytes={}-", aligned_start));
        }
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(_) => {
            return (StatusCode::NOT_FOUND, "Upstream request failed".to_string())
                .into_response()
        }
    };

    if !upstream.status().is_success() {
        return (
            StatusCode::NOT_FOUND,
            "Upstream status not OK".to_string(),
        )
            .into_response();
    }

    let key = blowfish_key(decrypt_id);
    let is_preview = url.contains("/preview/");
    let mut carry: Vec<u8> = Vec::with_capacity(4096);
    let upstream_headers = upstream.headers().clone();
    let upstream_total = upstream_headers
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_total_from_content_range)
        // For full (non-range) requests, CDN returns Content-Length directly
        .or_else(|| {
            upstream_headers
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
        });

    let mut upstream = upstream.bytes_stream();

    let out = async_stream::stream! {
        let mut drop_bytes = drop_bytes;
        let mut remaining = remaining;
        let mut done = false;
        while let Some(chunk_res) = upstream.next().await {
            let chunk = match chunk_res {
                Ok(c) => c,
                Err(e) => {
                    yield Err::<Bytes, BoxErr>(Box::new(e));
                    break;
                }
            };

            carry.extend_from_slice(&chunk);

            while carry.len() >= 2048 {
                let mut block = carry.drain(0..2048).collect::<Vec<u8>>();
                if !is_preview && block_index % 3 == 0 {
                    let _ = decrypt_stripe(&mut block, &key);
                }
                block_index += 1;
                if drop_bytes > 0 {
                    if drop_bytes >= block.len() {
                        drop_bytes -= block.len();
                        continue;
                    }
                    block = block.split_off(drop_bytes);
                    drop_bytes = 0;
                }
                if let Some(rem) = remaining {
                    if rem == 0 {
                        done = true;
                        break;
                    }
                    if (block.len() as u64) > rem {
                        block.truncate(rem as usize);
                        remaining = Some(0);
                        yield Ok::<Bytes, BoxErr>(Bytes::from(block));
                        done = true;
                        break;
                    } else {
                        remaining = Some(rem - block.len() as u64);
                    }
                }
                yield Ok::<Bytes, BoxErr>(Bytes::from(block));
            }
            if done { break; }
        }

        if !done && !carry.is_empty() {
            let mut tail = std::mem::take(&mut carry);
            if drop_bytes > 0 {
                if drop_bytes < tail.len() {
                    tail = tail.split_off(drop_bytes);
                } else {
                    tail.clear();
                }
            }
            if !tail.is_empty() {
                if let Some(rem) = remaining {
                    if rem > 0 {
                        if (tail.len() as u64) > rem {
                            tail.truncate(rem as usize);
                        }
                        yield Ok::<Bytes, BoxErr>(Bytes::from(tail));
                    }
                } else {
                    yield Ok::<Bytes, BoxErr>(Bytes::from(tail));
                }
            }
        }
    };

    let upstream_content_type_str = upstream_headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("audio/mpeg");

    let body = Body::from_stream(out);
    let mut resp = axum::response::Response::new(body);
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_str(upstream_content_type_str).unwrap());
    resp.headers_mut()
        .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));

    if let Some((start, end)) = req_range {
        if let Some(total) = upstream_total {
            let end_for_hdr = end.unwrap_or_else(|| total.saturating_sub(1));
            if end_for_hdr >= start {
                let _ = resp.headers_mut().insert(
                    CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end_for_hdr, total))
                        .unwrap_or_else(|_| HeaderValue::from_static("bytes 0-0/*")),
                );
                let len = end_for_hdr.saturating_sub(start).saturating_add(1);
                let _ = resp
                    .headers_mut()
                    .insert(CONTENT_LENGTH, HeaderValue::from_str(&len.to_string()).unwrap());
                *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
            }
        } else if let Some(end_for_hdr) = end {
            if end_for_hdr >= start {
                let _ = resp.headers_mut().insert(
                    CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end_for_hdr, "*"))
                        .unwrap_or_else(|_| HeaderValue::from_static("bytes 0-0/*")),
                );
                let len = end_for_hdr.saturating_sub(start).saturating_add(1);
                let _ = resp
                    .headers_mut()
                    .insert(CONTENT_LENGTH, HeaderValue::from_str(&len.to_string()).unwrap());
                *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
            }
        }
    } else {
        if let Some(total) = upstream_total {
            let _ = resp
                .headers_mut()
                .insert(CONTENT_LENGTH, HeaderValue::from_str(&total.to_string()).unwrap());
        }
    }

    resp
}

#[derive(Debug, Deserialize)]
struct UserDataReq {
    arl: String,
}

async fn user_data(State(state): State<AppState>, Json(req): Json<UserDataReq>) -> impl IntoResponse {
    let arl = req.arl.trim().to_string();
    if arl.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "ARL required");
    }

    let client = api_client_for_arl(&state, Some(arl)).await;
    let data = {
        let mut client = client.lock().await;
        match client.user_data().await {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
        }
    };

    let token = data["checkForm"].as_str().unwrap_or("").to_string();
    let uid = data["USER"]["USER_ID"].as_i64().map(|n| n.to_string()).unwrap_or_default();

    (StatusCode::OK, Json(json!({ "token": token, "uid": uid }))).into_response()
}

#[derive(Debug, Deserialize)]
struct PlaylistsReq {
    arl: String,
    start: Option<u32>,
    nb: Option<u32>,
}

async fn playlists(State(state): State<AppState>, Json(req): Json<PlaylistsReq>) -> impl IntoResponse {
    let arl = req.arl.trim().to_string();
    if arl.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "ARL required");
    }

    let client = api_client_for_arl(&state, Some(arl)).await;
    let res = {
        let mut client = client.lock().await;
        let ud = match client.user_data().await {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
        };

        let uid = ud["USER"]["USER_ID"].as_i64().unwrap_or(0);
        if uid <= 0 {
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "No USER_ID");
        }

        let start = req.start.unwrap_or(0);
        let nb = req.nb.unwrap_or(50);

        let res: Result<serde_json::Value, APIError> = client
            .api_call("playlist.getList", &json!({"user_id":uid,"nb":nb,"start":start}))
            .await;
        res
    };

    match res {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct PlaylistTracksReq {
    arl: String,
    playlist_id: u64,
    start: Option<u32>,
    nb: Option<u32>,
}

async fn playlist_tracks(
    State(state): State<AppState>,
    Json(req): Json<PlaylistTracksReq>,
) -> impl IntoResponse {
    let arl = req.arl.trim().to_string();
    if arl.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "ARL required");
    }

    let client = api_client_for_arl(&state, Some(arl)).await;

    let start = req.start.unwrap_or(0);
    let nb = req.nb.unwrap_or(100);

    let res: Result<serde_json::Value, APIError> = {
        let mut client = client.lock().await;
        let _ = client.user_data().await;
        client
            .api_call(
                "playlist.getSongs",
                &json!({
                    "playlist_id": req.playlist_id,
                    "start": start,
                    "nb": nb
                }),
            )
            .await
    };

    match res {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct LoginReq {
    email: String,
    password_md5: String,
}

#[derive(Deserialize)]
struct GwResp {
    error: serde_json::Value,
    results: serde_json::Value,
}

// ── Мобильный API Deezer ──────────────────────────────────────────────────
// Использует api.deezer.com/1.0/gateway.php с мобильным UA — не блокируется CF
const MOBILE_UA:      &str = "Deezer/8.32.0.2 (iOS; 14.4; Mobile; en; iPhone10_5)";
const MOBILE_API_KEY: &str = "ZAIVAHCEISOHWAICUQUEXAEPICENGUAFAEZAIPHAELEEVAHPHUCUFONGUAPASUAY";
const MOBILE_GW:      &str = "https://api.deezer.com/1.0/gateway.php";

/// Построить reqwest::Client с мобильным UA и нужными cookie
fn mobile_client_with_arl(arl: &str) -> reqwest::Client {
    let jar = Arc::new(Jar::default());
    let url = "https://api.deezer.com".parse::<Url>().unwrap();
    if !arl.is_empty() {
        jar.add_cookie_str(&format!("arl={}; Domain=.deezer.com", arl), &url);
        jar.add_cookie_str(&format!("arl={}; Domain=.api.deezer.com", arl), &url);
    }
    reqwest::Client::builder()
        .no_proxy()
        .cookie_provider(jar)
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap()
}

/// Вызов мобильного gateway.php
async fn mobile_gw(
    client: &reqwest::Client,
    method: &str,
    api_token: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let cid = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string());

    let r = client
        .post(MOBILE_GW)
        .query(&[
            ("method",      method),
            ("api_version", "1.0"),
            ("api_token",   api_token),
            ("input",       "3"),
            ("output",      "3"),
            ("cid",         cid.as_str()),
            ("api_key",     MOBILE_API_KEY),
        ])
        .header("User-Agent",       MOBILE_UA)
        .header("Content-Type",     "application/json; charset=UTF-8")
        .header("Accept",           "*/*")
        .header("Accept-Language",  "en-US")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("mobile_gw:network:{e}"))?;

    let status = r.status();
    let text = r.text().await.map_err(|_| "mobile_gw:read".to_string())?;

    if !status.is_success() {
        return Err(format!("mobile_gw:http:{}:{}", status.as_u16(), &text[..text.len().min(120)]));
    }

    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| format!("mobile_gw:parse:{}", &text[..text.len().min(120)]))?;

    // Проверяем поле error
    if let Some(err) = v.get("error") {
        if let Some(obj) = err.as_object() {
            if !obj.is_empty() {
                let msg = obj.iter()
                    .map(|(k, v)| format!("{k}:{}", v.as_str().unwrap_or("?")))
                    .collect::<Vec<_>>()
                    .join(";");
                return Err(format!("mobile_gw:deezer:{msg}"));
            }
        }
    }

    v.get("results")
        .cloned()
        .ok_or_else(|| format!("mobile_gw:no_results:{}", &text[..text.len().min(120)]))
}

/// Получить checkForm и SESSION через мобильный API (без ARL — анонимная сессия)
async fn mobile_get_user_data(client: &reqwest::Client) -> Result<serde_json::Value, String> {
    mobile_gw(client, "deezer.getUserData", "null", json!({})).await
}

/// Логин по email+md5(password) через мобильный API — возвращает ARL
async fn mobile_login(email: &str, password_md5: &str) -> Result<String, String> {
    let client = mobile_client_with_arl("");

    // Шаг 1: получаем checkForm (анонимная сессия)
    let ud = mobile_get_user_data(&client).await
        .map_err(|e| format!("mobile:getUserData:{e}"))?;

    let check_form = ud["checkForm"].as_str().unwrap_or("").to_string();
    if check_form.is_empty() {
        return Err("mobile:no_checkForm".to_string());
    }

    // Шаг 2: checkCredentials
    let creds_result = mobile_gw(&client, "user.checkCredentials", &check_form, json!({
        "login": email,
        "password": password_md5,
        "checkFormLogin": check_form
    })).await;

    // checkCredentials возвращает {} при успехе, ошибку при неверных данных
    if let Err(e) = &creds_result {
        // Неверный логин/пароль
        return Err(format!("mobile:checkCredentials:{e}"));
    }

    // Шаг 3: после checkCredentials сессия аутентифицирована — получаем свежий checkForm
    let ud2 = mobile_get_user_data(&client).await
        .map_err(|e| format!("mobile:getUserData2:{e}"))?;

    let check_form2 = ud2["checkForm"].as_str().unwrap_or("").to_string();
    if check_form2.is_empty() {
        return Err("mobile:no_checkForm2".to_string());
    }

    // Шаг 4: getArl
    let arl_result = mobile_gw(&client, "user.getArl", &check_form2, json!({})).await
        .map_err(|e| format!("mobile:getArl:{e}"))?;

    let arl = arl_result.as_str().unwrap_or("").to_string();
    if arl.len() < 100 {
        return Err(format!("mobile:arl_too_short:{}", arl.len()));
    }

    Ok(arl)
}

const DEEZER_APP_SECRET: &str = "a83bf7f38ad2f137e444727cfc3775cf";

struct WebLoginResult {
    arl: Option<String>,
    token: String,
    uid: String,
    access_token: String,
    license_token: String,
}

fn gw_browser_ua() -> &'static str {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}

fn gw_cid() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn capture_sid_from_response(jar: &Jar, url: &Url, headers: &reqwest::header::HeaderMap) {
    for cookie_hdr in headers.get_all(reqwest::header::SET_COOKIE) {
        if let Ok(s) = cookie_hdr.to_str() {
            for part in s.split(',') {
                let part = part.trim();
                let name_val = part.split(';').next().unwrap_or("").trim();
                if name_val.starts_with("sid=") {
                    jar.add_cookie_str(
                        &format!("{name_val}; Domain=.deezer.com; Path=/"),
                        url,
                    );
                }
            }
        }
    }
}

/// Deezer выдаёт анонимный sid в Set-Cookie ответа на GET user.getArl — нужен до OAuth.
async fn ensure_anonymous_sid(client: &reqwest::Client, jar: &Jar) -> Result<(), String> {
    let url_deezer = "https://www.deezer.com".parse::<Url>().map_err(|_| "sid:url".to_string())?;
    if jar_has_cookie(jar, &url_deezer, "sid=") {
        return Ok(());
    }

    let cid = gw_cid();
    let r = client
        .get("https://www.deezer.com/ajax/gw-light.php")
        .query(&[
            ("method", "user.getArl"),
            ("input", "3"),
            ("output", "3"),
            ("api_version", "1.0"),
            ("api_token", "null"),
            ("cid", cid.as_str()),
        ])
        .header(ACCEPT, "*/*")
        .header("Origin", "https://www.deezer.com")
        .header("Referer", "https://www.deezer.com/")
        .header("Sec-Fetch-Site", "same-origin")
        .header("Sec-Fetch-Mode", "cors")
        .header("Sec-Fetch-Dest", "empty")
        .header("User-Agent", gw_browser_ua())
        .send()
        .await
        .map_err(|e| format!("sid:network:{e}"))?;

    capture_sid_from_response(jar, &url_deezer, r.headers());

    if !jar_has_cookie(jar, &url_deezer, "sid=") {
        return Err("sid:not_set".to_string());
    }
    Ok(())
}

async fn gw_fetch_arl(
    client: &reqwest::Client,
    email: &str,
    password_md5: &str,
    user_id: Option<&str>,
) -> Result<(String, String, String, String), String> {
    let mut last_err = String::from("getArl:none");

    for attempt in 0..3u8 {
        let ud = gw_light_call_custom(
            client,
            "deezer.getUserData",
            "null",
            None,
            &json!({}),
            None,
            attempt > 0,
            None,
        )
        .await
        .map_err(|e| format!("getUserData:{e}"))?;

        let check_form = ud
            .get("checkForm")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if check_form.is_empty() {
            last_err = "no_checkForm".to_string();
            continue;
        }

        let uid = ud
            .get("USER")
            .and_then(|u| u.get("USER_ID"))
            .and_then(|x| x.as_i64())
            .map(|n| n.to_string())
            .unwrap_or_default();

        let uid_for_hdr = user_id
            .filter(|s| !s.trim().is_empty())
            .or_else(|| if uid.is_empty() { None } else { Some(uid.as_str()) });

        match gw_light_call_custom(
            client,
            "user.getArl",
            &check_form,
            None,
            &json!({}),
            uid_for_hdr,
            true,
            None,
        )
        .await
        {
            Ok(v) => {
                let arl = v.as_str().unwrap_or("").to_string();
                if arl.len() >= 100 {
                    let license_token = license_token_from_ud(&ud);
                    return Ok((arl, check_form, uid, license_token));
                }
                last_err = format!("arl_too_short:{}", arl.len());
            }
            Err(e) => {
                last_err = e.clone();
                if e.contains("NEED_USER_AUTH") && attempt == 0 {
                    let _ = gw_light_call_custom(
                        client,
                        "user.checkCredentials",
                        &check_form,
                        None,
                        &json!({
                            "login": email,
                            "password": password_md5,
                            "checkFormLogin": check_form
                        }),
                        uid_for_hdr,
                        false,
                        None,
                    )
                    .await;
                }
            }
        }
    }

    Err(format!("getArl:{last_err}"))
}

async fn try_fetch_arl_for_token(
    access_token: &str,
    user_id: Option<&str>,
) -> (Option<String>, Option<String>, Option<String>) {
    let jar = Arc::new(Jar::default());
    let url_deezer = match "https://www.deezer.com".parse::<Url>() {
        Ok(u) => u,
        Err(_) => return (None, None, None),
    };
    jar.add_cookie_str("comeback=1; Domain=.deezer.com; Path=/", &url_deezer);

    let client = match reqwest::Client::builder()
        .no_proxy()
        .cookie_provider(jar.clone())
        .timeout(std::time::Duration::from_secs(20))
        .build()
    {
        Ok(c) => c,
        Err(_) => return (None, None, None),
    };

    let _ = client
        .get("https://www.deezer.com/")
        .header(ACCEPT, "*/*")
        .header("User-Agent", gw_browser_ua())
        .send()
        .await;

    if ensure_anonymous_sid(&client, &jar).await.is_err() {
        return (None, None, None);
    }

    establish_oauth_session(&client, &jar, access_token).await;

    let uid = if let Some(uid) = user_id.filter(|s| !s.trim().is_empty()) {
        Some(uid.to_string())
    } else {
        api_deezer_get(&client, "/user/me", access_token, &[])
            .await
            .ok()
            .and_then(|v| v.get("id").and_then(|x| x.as_i64()))
            .filter(|id| *id > 0)
            .map(|id| id.to_string())
    };

    match gw_fetch_arl(&client, "", "", uid.as_deref()).await {
        Ok((arl, token, _, license_token)) if arl.len() >= 20 => {
            let gw_token = if token.is_empty() { None } else { Some(token) };
            let lic = if license_token.is_empty() { None } else { Some(license_token) };
            (Some(arl), gw_token, lic)
        }
        _ => (None, None, None),
    }
}

async fn oauth_access_token(
    client: &reqwest::Client,
    email: &str,
    password_md5: &str,
) -> Result<String, String> {
    let app_id = deezer_app_id();
    let hash_src = format!("{app_id}{email}{password_md5}{DEEZER_APP_SECRET}");
    let hash = format!("{:x}", md5::compute(hash_src.as_bytes()));

    let r = client
        .get("https://connect.deezer.com/oauth/user_auth.php")
        .query(&[
            ("app_id", app_id.as_str()),
            ("login", email),
            ("password", password_md5),
            ("hash", hash.as_str()),
        ])
        .header(ACCEPT, "*/*")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        )
        .send()
        .await
        .map_err(|e| format!("network:{e}"))?;

    let status = r.status();
    let text = r.text().await.map_err(|_| "read".to_string())?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
        let snip: String = text.chars().take(200).collect();
        format!("parse:{}:{}", status.as_u16(), snip)
    })?;

    if let Some(err) = v.get("error") {
        return Err(err.as_str().unwrap_or("error").to_string());
    }

    let token = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    if token.is_empty() {
        return Err("no_token".to_string());
    }
    Ok(token)
}

async fn establish_oauth_session(client: &reqwest::Client, jar: &Jar, access_token: &str) {
    let url_deezer = "https://www.deezer.com".parse::<Url>().unwrap();
    let url_api = "https://api.deezer.com".parse::<Url>().unwrap();
    let ua = gw_browser_ua();

    let _ = client
        .get("https://api.deezer.com/user/me")
        .query(&[("access_token", access_token)])
        .header("Authorization", format!("Bearer {access_token}"))
        .header(ACCEPT, "*/*")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("User-Agent", ua)
        .send()
        .await;

    let _ = client
        .get("https://api.deezer.com/platform/generic/track/80085")
        .header("Authorization", format!("Bearer {access_token}"))
        .header(ACCEPT, "*/*")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("User-Agent", ua)
        .send()
        .await;

    if !jar_has_cookie(jar, &url_deezer, "sid=") && !jar_has_cookie(jar, &url_api, "sid=") {
        let _ = client
            .get("https://api.deezer.com/platform/generic/track/3135556")
            .header("Authorization", format!("Bearer {access_token}"))
            .header(ACCEPT, "*/*")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("User-Agent", ua)
            .send()
            .await;
    }
}

async fn web_login(email: &str, password_md5: &str) -> Result<WebLoginResult, String> {
    let jar = Arc::new(Jar::default());
    let url_deezer = "https://www.deezer.com".parse::<Url>().map_err(|_| "web:url".to_string())?;
    jar.add_cookie_str("comeback=1; Domain=.deezer.com; Path=/", &url_deezer);

    let client = reqwest::Client::builder()
        .no_proxy()
        .cookie_provider(jar.clone())
        .timeout(std::time::Duration::from_secs(25))
        .build()
        .map_err(|_| "web:client".to_string())?;

    let _ = client
        .get("https://www.deezer.com/")
        .header(ACCEPT, "*/*")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("User-Agent", gw_browser_ua())
        .send()
        .await;

    // sid нужен ДО OAuth (как в официальном клиенте Deezer)
    ensure_anonymous_sid(&client, &jar)
        .await
        .map_err(|e| format!("web:{e}"))?;

    let access_token = oauth_access_token(&client, email, password_md5)
        .await
        .map_err(|e| format!("oauth:{e}"))?;

    establish_oauth_session(&client, &jar, &access_token).await;

    let _ = client
        .get("https://www.deezer.com/")
        .header(ACCEPT, "*/*")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("User-Agent", gw_browser_ua())
        .send()
        .await;

    let uid_from_api = api_deezer_get(
        &client,
        "/user/me",
        &access_token,
        &[],
    )
    .await
    .ok()
    .and_then(|v| v.get("id").and_then(|x| x.as_i64()))
    .filter(|id| *id > 0)
    .map(|id| id.to_string());

    let (arl, token, uid, license_token) = match gw_fetch_arl(
        &client,
        email,
        password_md5,
        uid_from_api.as_deref(),
    )
    .await
    {
        Ok(v) => v,
        Err(_e) => {
            if let Ok(mobile_arl) = mobile_login(email, password_md5).await {
                (
                    mobile_arl,
                    String::new(),
                    uid_from_api.clone().unwrap_or_default(),
                    String::new(),
                )
            } else {
                return Ok(WebLoginResult {
                    arl: None,
                    token: String::new(),
                    uid: uid_from_api.unwrap_or_default(),
                    access_token,
                    license_token: String::new(),
                });
            }
        }
    };

    Ok(WebLoginResult {
        arl: Some(arl.clone()),
        token,
        uid: if uid.is_empty() {
            uid_from_api.unwrap_or_default()
        } else {
            uid
        },
        access_token,
        license_token,
    })
}

fn worker_base() -> Option<String> {
    let env = std::env::var("DZMEDIA_WORKER").ok().unwrap_or_default();
    let base = env.trim();
    if base.is_empty() || base == "-" {
        return None;
    }
    Some(base.trim_end_matches('/').to_string())
}

#[derive(Serialize)]
struct WorkerLoginReq<'a> {
    email: &'a str,
    password_md5: &'a str,
}

#[derive(Deserialize)]
struct WorkerLoginResp {
    arl: Option<String>,
    error: Option<String>,
}

async fn worker_login(email: &str, password_md5: &str) -> Result<String, String> {
    let Some(base) = worker_base() else {
        return Err("worker:disabled".to_string());
    };
    let url = format!("{base}/login");

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(25))
        .build()
        .map_err(|_| "worker:client".to_string())?;

    let r = client
        .post(url)
        .json(&WorkerLoginReq { email, password_md5 })
        .send()
        .await
        .map_err(|e| format!("worker:network:{e}"))?;

    let status = r.status();
    let text = r.text().await.map_err(|_| "worker:read".to_string())?;
    if !status.is_success() {
        let snip: String = text.chars().take(200).collect();
        return Err(format!("worker:http:{}:{}", status.as_u16(), snip));
    }
    let v: WorkerLoginResp = serde_json::from_str(&text).map_err(|_| {
        let snip: String = text.chars().take(200).collect();
        format!("worker:parse:{snip}")
    })?;
    if let Some(arl) = v.arl {
        if arl.len() >= 100 {
            return Ok(arl);
        }
        return Err(format!("worker:arl_too_short:{}", arl.len()));
    }
    Err(format!("worker:error:{}", v.error.unwrap_or_else(|| "unknown".to_string())))
}


async fn gw_light_call(
    client: &reqwest::Client,
    _jar: &Arc<Jar>,
    method: &str,
    api_token: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let url = "https://www.deezer.com/ajax/gw-light.php";
    let url_deezer = "https://www.deezer.com".parse::<Url>().unwrap();

    fn cid() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis().to_string())
            .unwrap_or_else(|_| "0".to_string())
    }

    async fn do_req(
        client: &reqwest::Client,
        _url_deezer: &Url,
        url: &str,
        method: &str,
        api_token: &str,
        params: &serde_json::Value,
        use_get: bool,
        user_id: Option<&str>,
    ) -> Result<serde_json::Value, String> {
        let cid = cid();
        let mut req = if use_get || method == "user.getArl" {
            client.get(url)
        } else {
            client
                .post(url)
                .header("Content-Type", "text/plain;charset=UTF-8")
                .body(params.to_string())
        };
        if let Some(uid) = user_id.filter(|s| !s.trim().is_empty()) {
            req = req.header("x-deezer-user", uid);
        }

        let r = req
            .query(&[
                ("method", method),
                ("input", "3"),
                ("output", "3"),
                ("api_version", "1.0"),
                ("api_token", api_token),
                ("cid", cid.as_str()),
            ])
            .header(ACCEPT, "*/*")
            .header("Cache-Control", "max-age=0")
            .header("Origin", "https://www.deezer.com")
            .header("Referer", "https://www.deezer.com/")
            .header("Sec-Fetch-Site", "same-origin")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Dest", "empty")
            .header("X-Requested-With", "XMLHttpRequest")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Content-Language", "en-US")
            .header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            )
            .header("sec-ch-ua", "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"")
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"Windows\"")
            .send()
            .await
            .map_err(|_| "network".to_string())?;

        let status = r.status();
        let text = r.text().await.map_err(|_| "read".to_string())?;
        if status.as_u16() == 403 && text.to_ascii_lowercase().contains("access denied") {
            return Err("blocked:403".to_string());
        }
        let json: GwResp = serde_json::from_str(&text).map_err(|_| {
            let snip: String = text.chars().take(200).collect();
            format!("parse:{}:{}", status.as_u16(), snip)
        })?;

        if let Some(error) = json.error.as_object() {
            for (code, message) in error {
                let msg = message.as_str().unwrap_or("");
                return Err(format!("{}:{}", code, msg));
            }
        }

        Ok(json.results)
    }

    if method == "deezer.getUserData" {
        // Только POST — GET вариант блокируется как бот
        match do_req(client, &url_deezer, url, method, api_token, &params, false, None).await {
            Ok(v) => Ok(v),
            Err(e1) => Err(format!("getUserData:{e1}; fallback:{e1}")),
        }
    } else {
        match do_req(client, &url_deezer, url, method, api_token, &params, false, None).await {
            Ok(v) => Ok(v),
            Err(e1) => match do_req(client, &url_deezer, url, method, api_token, &params, false, None).await {
                Ok(v) => Ok(v),
                Err(e2) => Err(format!("{e1}; retry:{e2}")),
            },
        }
    }
}

async fn gw_light_call_custom(
    client: &reqwest::Client,
    method: &str,
    api_token: &str,
    gateway_input: Option<&str>,
    params: &serde_json::Value,
    user_id: Option<&str>,
    use_get: bool,
    lang: Option<&str>,
) -> Result<serde_json::Value, String> {
    fn cid() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis().to_string())
            .unwrap_or_else(|_| "0".to_string())
    }

    let cid = cid();
    let mut req = if use_get || method == "user.getArl" {
        client.get("https://www.deezer.com/ajax/gw-light.php")
    } else {
        client
            .post("https://www.deezer.com/ajax/gw-light.php")
            .header("Content-Type", "text/plain;charset=UTF-8")
            .body(params.to_string())
    };

    if let Some(uid) = user_id.filter(|s| !s.trim().is_empty()) {
        req = req.header("x-deezer-user", uid);
    }

    let mut qp: Vec<(&str, &str)> = vec![
        ("method", method),
        ("input", "3"),
        ("output", "3"),
        ("api_version", "1.0"),
        ("api_token", api_token),
        ("cid", cid.as_str()),
    ];
    if let Some(gi) = gateway_input.filter(|s| !s.trim().is_empty()) {
        qp.push(("gateway_input", gi));
    }

    let r = req
        .query(&qp)
        .header(ACCEPT, "*/*")
        .header("Cache-Control", "max-age=0")
        .header("Origin", "https://www.deezer.com")
        .header("Referer", "https://www.deezer.com/")
        .header("Sec-Fetch-Site", "same-origin")
        .header("Sec-Fetch-Mode", "cors")
        .header("Sec-Fetch-Dest", "empty")
        .header("X-Requested-With", "XMLHttpRequest")
        .header("Accept-Language", format!("{},en;q=0.9", lang.unwrap_or("en-US")))
        .header("Content-Language", lang.unwrap_or("en-US"))
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        )
        .send()
        .await
        .map_err(|_| "network".to_string())?;

    let status = r.status();
    let text = r.text().await.map_err(|_| "read".to_string())?;
    if status.as_u16() == 403 && text.to_ascii_lowercase().contains("access denied") {
        return Err("blocked:403".to_string());
    }
    let json: GwResp = serde_json::from_str(&text).map_err(|_| {
        let snip: String = text.chars().take(200).collect();
        format!("parse:{}:{}", status.as_u16(), snip)
    })?;

    if let Some(error) = json.error.as_object() {
        for (code, message) in error {
            let msg = message.as_str().unwrap_or("");
            return Err(format!("{}:{}", code, msg));
        }
    }

    Ok(json.results)
}

fn jar_has_cookie(jar: &Jar, url: &Url, cookie_prefix: &str) -> bool {
    let Some(hv) = jar.cookies(url) else { return false };
    let Ok(s) = hv.to_str() else { return false };
    s.split(';').any(|p| p.trim_start().starts_with(cookie_prefix))
}

async fn login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> impl IntoResponse {
    let email = req.email.trim().to_string();
    let pass  = req.password_md5.trim().to_string();

    if email.is_empty() || pass.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "Email and password_md5 required");
    }

    match web_login(&email, &pass).await {
        Ok(res) => {
            if let Some(ref arl) = res.arl {
                store_arl_session(&state, arl, &res.token, &res.license_token).await;
                state.api_by_arl.write().await.remove(arl);
            }
            (StatusCode::OK, Json(json!({
                "arl":          res.arl,
                "token":        res.token,
                "uid":          res.uid,
                "access_token": res.access_token
            }))).into_response()
        }
        Err(e) => json_error(
            StatusCode::UNAUTHORIZED,
            format!("login_failed; {e}"),
        ),
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct PairSession {
    created_ms: u128,
    access_token: Option<String>,
    token: Option<String>,
    user_id: Option<String>,
    email: Option<String>,
    arl: Option<String>,
    error: Option<String>,
}

async fn pair_store_load(state: &AppState) {
    let path = state.pair_store_path.trim();
    if path.is_empty() {
        return;
    }
    if let Ok(txt) = tokio::fs::read_to_string(path).await {
        if let Ok(map) = serde_json::from_str::<HashMap<String, PairSession>>(&txt) {
            *state.pair.write().await = map;
        }
    }
}

async fn pair_store_save(state: &AppState) {
    let path = state.pair_store_path.trim();
    if path.is_empty() {
        return;
    }
    let map = state.pair.read().await.clone();
    let Ok(txt) = serde_json::to_string(&map) else { return };
    let tmp = format!("{path}.tmp");
    if tokio::fs::write(&tmp, txt).await.is_ok() {
        if tokio::fs::rename(&tmp, path).await.is_err() {
            let _ = tokio::fs::remove_file(path).await;
            let _ = tokio::fs::rename(&tmp, path).await;
        }
    }
}

fn gen_pair_code() -> String {
    let ms = now_ms();
    let hex = format!("{:x}", md5::compute(format!("pair:{ms}:{SECRET}").as_bytes()));
    hex.chars().take(10).collect::<String>()
}

fn deezer_app_id() -> String {
    std::env::var("DEEZER_APP_ID")
        .ok()
        .unwrap_or_else(|| "447462".to_string())
        .trim()
        .to_string()
}

fn forwarded_proto(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http")
        .trim()
        .to_string()
}

fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for &b in s.as_bytes() {
        let c = b as char;
        let ok = matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~');
        if ok {
            out.push(c);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

#[derive(Deserialize)]
struct PairStatusQuery {
    code: String,
}

async fn pair_start(State(state): State<AppState>) -> impl IntoResponse {
    let code = gen_pair_code();
    let created_ms = now_ms();
    {
        let mut map = state.pair.write().await;
        let now = created_ms;
        let ttl_ms: u128 = 10 * 60 * 1000;
        map.retain(|_, v| now.saturating_sub(v.created_ms) <= ttl_ms);
        if map.len() >= 512 {
            map.clear();
        }
        map.insert(
            code.clone(),
            PairSession {
                created_ms,
                access_token: None,
                token: None,
                user_id: None,
                email: None,
                arl: None,
                error: None,
            },
        );
    }
    pair_store_save(&state).await;
    (StatusCode::OK, Json(json!({ "code": code }))).into_response()
}

async fn pair_status(State(state): State<AppState>, Query(q): Query<PairStatusQuery>) -> impl IntoResponse {
    let code = q.code.trim().to_string();
    if code.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "code required");
    }

    let now = now_ms();
    let ttl_ms: u128 = 10 * 60 * 1000;
    let mut map = state.pair.write().await;
    let Some(sess) = map.get(&code) else {
        return json_error(StatusCode::NOT_FOUND, "no such code");
    };
    if now.saturating_sub(sess.created_ms) > ttl_ms {
        map.remove(&code);
        drop(map);
        pair_store_save(&state).await;
        return json_error(StatusCode::NOT_FOUND, "code expired");
    }

    if let Some(err) = &sess.error {
        return (StatusCode::OK, Json(json!({ "status": "error", "error": err }))).into_response();
    }
    if let Some(tok) = &sess.access_token {
        return (
            StatusCode::OK,
            Json(json!({ "status": "ok", "access_token": tok, "token": sess.token, "user_id": sess.user_id, "email": sess.email, "arl": sess.arl })),
        )
            .into_response();
    }
    if sess.arl.as_deref().unwrap_or("").len() > 20 {
        return (
            StatusCode::OK,
            Json(json!({ "status": "ok", "access_token": null, "token": sess.token, "user_id": sess.user_id, "email": sess.email, "arl": sess.arl })),
        )
            .into_response();
    }
    if sess.token.as_deref().unwrap_or("").trim().len() > 0 {
        return (
            StatusCode::OK,
            Json(json!({ "status": "ok", "access_token": null, "token": sess.token, "user_id": sess.user_id, "email": sess.email, "arl": sess.arl })),
        )
            .into_response();
    }

    (StatusCode::OK, Json(json!({ "status": "pending" }))).into_response()
}

#[derive(Deserialize)]
struct PairPageQuery {
    code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PairOauthReq {
    code: String,
    access_token: String,
    user_id: Option<String>,
}

async fn pair_oauth(State(state): State<AppState>, Json(req): Json<PairOauthReq>) -> impl IntoResponse {
    let code = req.code.trim().to_string();
    let access_token = req.access_token.trim().to_string();
    let user_id = req
        .user_id
        .unwrap_or_default()
        .trim()
        .to_string()
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>();
    if code.is_empty() || access_token.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "code/access_token required");
    }

    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();
    let email = api_deezer_get(&http, "/user/me", &access_token, &[])
        .await
        .ok()
        .and_then(|v| v.get("email").and_then(|x| x.as_str()).map(|s| s.to_string()));

    let uid_from_api = if user_id.is_empty() {
        api_deezer_get(&http, "/user/me", &access_token, &[])
            .await
            .ok()
            .and_then(|v| v.get("id").and_then(|x| x.as_i64()))
            .filter(|id| *id > 0)
            .map(|id| id.to_string())
    } else {
        Some(user_id.clone())
    };

    let (arl_opt, token_opt, license_opt) = try_fetch_arl_for_token(
        &access_token,
        uid_from_api.as_deref(),
    )
    .await;

    if let (Some(ref arl), Some(ref token), Some(ref lic)) = (&arl_opt, &token_opt, &license_opt) {
        store_arl_session(&state, arl, token, lic).await;
        state.api_by_arl.write().await.remove(arl);
    } else if let (Some(ref arl), Some(ref token)) = (&arl_opt, &token_opt) {
        store_arl_session(&state, arl, token, "").await;
        state.api_by_arl.write().await.remove(arl);
    }

    let mut map = state.pair.write().await;
    let Some(sess) = map.get_mut(&code) else {
        return json_error(StatusCode::NOT_FOUND, "no such code");
    };
    sess.access_token = Some(access_token);
    if let Some(uid) = uid_from_api {
        sess.user_id = Some(uid);
    }
    if let Some(arl) = arl_opt {
        sess.arl = Some(arl);
    }
    if let Some(token) = token_opt {
        sess.token = Some(token);
    }
    if let Some(email) = email {
        sess.email = Some(email);
    }
    sess.error = None;
    drop(map);
    pair_store_save(&state).await;
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

async fn pair_channel() -> impl IntoResponse {
    let html = "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"></head><body></body></html>";
    (StatusCode::OK, Html(html.to_string())).into_response()
}

async fn pair_page(Host(host): Host, headers: HeaderMap, Query(q): Query<PairPageQuery>) -> impl IntoResponse {
    let code = q.code.unwrap_or_default().trim().to_string();
    let safe_code = htmlesc(&code);
    let scheme = forwarded_proto(&headers);
    let app_id = deezer_app_id();
    let redirect_url = format!("{scheme}://{host}/pair/oauth_cb");
    let oauth_url = format!(
        "https://connect.deezer.com/oauth/auth.php?app_id={}&redirect_uri={}&perms={}&response_type=token&state={}",
        urlenc(&app_id),
        urlenc(&redirect_url),
        urlenc("basic_access,email,manage_library,listening_history"),
        urlenc(&code)
    );

    let code_js = serde_json::to_string(&code).unwrap_or_else(|_| "\"\"".to_string());
    let oauth_url_js = serde_json::to_string(&oauth_url).unwrap_or_else(|_| "\"\"".to_string());
    let redirect_url_txt = htmlesc(&redirect_url);

    let mut html = String::with_capacity(6000);
    html.push_str(r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">"#);
    html.push_str(r#"<title>Deezer Login</title>"#);
    html.push_str(r#"<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0b0b0b;color:#fff;margin:0;padding:20px}.box{max-width:420px;margin:0 auto;background:#151515;padding:18px;border-radius:12px}button{width:100%;padding:12px 14px;border-radius:10px;border:0;background:#a238ff;color:#fff;font-weight:800;font-size:16px}.muted{color:#aaa;font-size:13px;line-height:1.35}.ok{color:#1db954}.err{color:#ff5a5a}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;background:#101010;border-radius:8px;padding:10px;word-break:break-all}a{color:#a238ff}input{width:100%;box-sizing:border-box;padding:12px 12px;border-radius:10px;border:1px solid #2b2b2b;background:#0f0f0f;color:#fff;outline:none}input:focus{border-color:#a238ff}.row{margin:10px 0 0}</style>"#);
    html.push_str(r#"</head><body><div class="box">"#);
    html.push_str(r#"<h2 style="margin:0 0 6px">Deezer: вход для ТВ</h2>"#);
    html.push_str(r#"<div class="muted">Код пары: <b>"#);
    html.push_str(&safe_code);
    html.push_str(r#"</b></div>"#);
    html.push_str(r#"<div class="muted" style="margin:10px 0 14px">Нажми кнопку, войди в Deezer и подтверди доступ. После успеха вернись на телевизор.</div>"#);
    html.push_str(r#"<button id="dz-login" type="button">Войти через Deezer</button>"#);
    html.push_str(r#"<div id="msg" class="muted" style="margin:12px 0 0"></div>"#);
    html.push_str(r#"<div class="muted" style="margin:12px 0 8px">Рекомендуется OAuth (кнопка выше). Вход по логину/паролю ниже может блокироваться на некоторых прокси/хостингах (403 Access Denied).</div>"#);
    html.push_str(r#"<form method="POST" action="/pair/complete" autocomplete="on" style="margin:10px 0 0" onsubmit="var b=this.querySelector('button');b.disabled=true;b.textContent='Вход... Пожалуйста, подождите';">"#);
    html.push_str(r#"<input type="hidden" name="code" value="" id="pair-code-hidden">"#);
    html.push_str(r#"<div class="row"><input name="email" type="email" placeholder="Email" autocomplete="username" required></div>"#);
    html.push_str(r#"<div class="row"><input name="password" type="password" placeholder="Пароль" autocomplete="current-password" required></div>"#);
    html.push_str(r#"<div class="row"><button type="submit">Войти по логину и паролю</button></div>"#);
    html.push_str(r#"</form>"#);
    html.push_str(r#"<div class="muted" style="margin:14px 0 8px">Redirect URI для Deezer приложения:</div>"#);
    html.push_str(r#"<div class="mono">"#);
    html.push_str(&redirect_url_txt);
    html.push_str(r#"</div>"#);
    html.push_str(r#"<script>(function(){"#);
    html.push_str("var code=");
    html.push_str(&code_js);
    html.push_str(r#";var oauthUrl="#);
    html.push_str(&oauth_url_js);
    html.push_str(r#";var msg=document.getElementById('msg');function setMsg(cls,text){msg.className=cls?(cls+' muted'):'muted';msg.textContent=text;}if(!code){setMsg('err','Нет кода пары. Открой ссылку заново с QR.');return;}var hidden=document.getElementById('pair-code-hidden');if(hidden){hidden.value=code;}document.getElementById('dz-login').addEventListener('click',function(){setMsg('','Открываю Deezer…');if(!oauthUrl){setMsg('err','Не удалось собрать Deezer OAuth URL');return;}window.location.href=oauthUrl;});})();</script>"#);
    html.push_str(r#"<p class="muted" style="margin:14px 0 0">Если Deezer пишет про неверный redirect/domain — нужно указать свой <b>DEEZER_APP_ID</b> для домена этого сервера.</p>"#);
    html.push_str(r#"</div></body></html>"#);
    Html(html)
}

#[derive(Deserialize)]
struct PairOauthCbQuery {
    code: Option<String>,
    state: Option<String>,
}

async fn pair_oauth_cb(Query(q): Query<PairOauthCbQuery>) -> impl IntoResponse {
    let code = q
        .code
        .or(q.state)
        .unwrap_or_default()
        .trim()
        .to_string();
    let safe_code = htmlesc(&code);
    let code_js = serde_json::to_string(&code).unwrap_or_else(|_| "\"\"".to_string());

    let mut html = String::with_capacity(3500);
    html.push_str(r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">"#);
    html.push_str(r#"<title>Deezer Login</title>"#);
    html.push_str(r#"<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0b0b0b;color:#fff;margin:0;padding:20px}.box{max-width:420px;margin:0 auto;background:#151515;padding:18px;border-radius:12px}.muted{color:#aaa;font-size:13px;line-height:1.35}.ok{color:#1db954}.err{color:#ff5a5a}</style>"#);
    html.push_str(r#"</head><body><div class="box">"#);
    html.push_str(r#"<h2 style="margin:0 0 6px">Deezer: вход для ТВ</h2>"#);
    html.push_str(r#"<div class="muted">Код пары: <b>"#);
    html.push_str(&safe_code);
    html.push_str(r#"</b></div>"#);
    html.push_str(r#"<div id="msg" class="muted" style="margin:12px 0 0">Получаю токен…</div>"#);
    html.push_str(r#"<script>(function(){"#);
    html.push_str("var codeFromQuery=");
    html.push_str(&code_js);
    html.push_str(r#";var msg=document.getElementById('msg');function setMsg(cls,text){msg.className=cls?(cls+' muted'):'muted';msg.textContent=text;}function parseHash(){var h=window.location.hash||'';if(h.charAt(0)==='#')h=h.slice(1);var out={};h.split('&').forEach(function(p){if(!p)return;var i=p.indexOf('=');var k=i>=0?p.slice(0,i):p;var v=i>=0?p.slice(i+1):'';try{k=decodeURIComponent(k);}catch(e){}try{v=decodeURIComponent(v);}catch(e){}out[k]=v;});return out;}var h=parseHash();var code=(codeFromQuery||h.state||'');if(!code){setMsg('err','Нет кода пары. Вернись на телевизор и обнови QR/ссылку.');return;}var at=h.access_token||'';if(!at){setMsg('err','Deezer не вернул access_token. Попробуй ещё раз.');return;}try{history.replaceState(null,'',window.location.pathname+window.location.search);}catch(e){}fetch('/pair/oauth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:code,access_token:at})}).then(function(r){return r.json().catch(function(){return {};}).then(function(j){return {ok:r.ok,json:j};});}).then(function(r){if(r.ok&&!r.json.error){setMsg('ok','Готово ✓ Вернись на телевизор.');}else{setMsg('err','Ошибка сохранения: '+(r.json.error||'error'));}}).catch(function(){setMsg('err','Ошибка сети при сохранении');});})();</script>"#);
    html.push_str(r#"</div></body></html>"#);
    (StatusCode::OK, Html(html)).into_response()
}

#[derive(Deserialize)]
struct PairCompleteForm {
    code: String,
    email: String,
    password: String,
}

fn htmlesc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn api_deezer_get(
    client: &reqwest::Client,
    path: &str,
    access_token: &str,
    extra: &[(&str, String)],
) -> Result<serde_json::Value, String> {
    let url = format!("https://api.deezer.com{path}");
    let mut req = client
        .get(url)
        .header("Authorization", format!("Bearer {}", access_token))
        .header(ACCEPT, "*/*")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        )
        .query(&[("access_token", access_token)]);
    if !extra.is_empty() {
        req = req.query(extra);
    }
    let r = req.send().await.map_err(|_| "api:network".to_string())?;
    let status = r.status();
    let text = r.text().await.map_err(|_| "api:read".to_string())?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
        let snip: String = text.chars().take(200).collect();
        format!("api:parse:{}:{}", status.as_u16(), snip)
    })?;
    if let Some(e) = v.get("error") {
        if e.is_object() {
            let code = e.get("code").and_then(|x| x.as_i64()).unwrap_or(0);
            let msg = e.get("message").and_then(|x| x.as_str()).unwrap_or("error");
            return Err(format!("api:{code}:{msg}"));
        }
        return Err("api:error".to_string());
    }
    Ok(v)
}

async fn api_deezer_post(
    client: &reqwest::Client,
    path: &str,
    access_token: &str,
    form: &[(&str, String)],
) -> Result<serde_json::Value, String> {
    let url = format!("https://api.deezer.com{path}");
    let mut req = client
        .post(url)
        .header("Authorization", format!("Bearer {}", access_token))
        .query(&[("access_token", access_token)]);
    if !form.is_empty() {
        req = req.form(form);
    }
    let r = req.send().await.map_err(|_| "api:network".to_string())?;
    let status = r.status();
    let text = r.text().await.map_err(|_| "api:read".to_string())?;
    
    if text.trim() == "true" {
        return Ok(json!(true));
    }
    if text.trim() == "false" {
        return Ok(json!(false));
    }
    
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
        let snip: String = text.chars().take(200).collect();
        format!("api:parse:{}:{}", status.as_u16(), snip)
    })?;
    if let Some(e) = v.get("error") {
        if e.is_object() {
            let code = e.get("code").and_then(|x| x.as_i64()).unwrap_or(0);
            let msg = e.get("message").and_then(|x| x.as_str()).unwrap_or("error");
            return Err(format!("api:{code}:{msg}"));
        }
        return Err("api:error".to_string());
    }
    Ok(v)
}

async fn api_deezer_delete(
    client: &reqwest::Client,
    path: &str,
    access_token: &str,
    query: &[(&str, String)],
) -> Result<serde_json::Value, String> {
    let url = format!("https://api.deezer.com{path}");
    let mut req = client
        .delete(url)
        .header("Authorization", format!("Bearer {}", access_token))
        .query(&[("access_token", access_token)]);
    if !query.is_empty() {
        req = req.query(query);
    }
    let r = req.send().await.map_err(|_| "api:network".to_string())?;
    let status = r.status();
    let text = r.text().await.map_err(|_| "api:read".to_string())?;
    
    if text.trim() == "true" {
        return Ok(json!(true));
    }
    if text.trim() == "false" {
        return Ok(json!(false));
    }
    
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
        let snip: String = text.chars().take(200).collect();
        format!("api:parse:{}:{}", status.as_u16(), snip)
    })?;
    if let Some(e) = v.get("error") {
        if e.is_object() {
            let code = e.get("code").and_then(|x| x.as_i64()).unwrap_or(0);
            let msg = e.get("message").and_then(|x| x.as_str()).unwrap_or("error");
            return Err(format!("api:{code}:{msg}"));
        }
        return Err("api:error".to_string());
    }
    Ok(v)
}

async fn pair_complete(State(state): State<AppState>, Form(f): Form<PairCompleteForm>) -> impl IntoResponse {
    let code     = f.code.trim().to_string();
    let email    = f.email.trim().to_string();
    let password = f.password;

    let html_head = r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Deezer Login</title><style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0b0b0b;color:#fff;margin:0;padding:20px}.box{max-width:420px;margin:0 auto;background:#151515;padding:18px;border-radius:12px}.muted{color:#aaa;font-size:13px;line-height:1.35}</style></head><body><div class="box">"#;
    let html_tail = r#"</div></body></html>"#;

    if code.is_empty() || email.is_empty() || password.is_empty() {
        return Html(format!("{html_head}<h3>Нужны code/email/password</h3>{html_tail}")).into_response();
    }

    {
        let map = state.pair.read().await;
        if !map.contains_key(&code) {
            return Html(format!("{html_head}<h3>Код не найден или истёк</h3>{html_tail}")).into_response();
        }
    }

    let pass_md5 = format!("{:x}", md5::compute(password.as_bytes()));

    let res = web_login(&email, &pass_md5).await;

    match res {
        Err(e) => {
            let mut map = state.pair.write().await;
            if let Some(s) = map.get_mut(&code) {
                s.error = Some(e.clone());
            }
            drop(map);
            pair_store_save(&state).await;
            Html(format!("{html_head}<h3>Ошибка входа</h3><pre style='white-space:pre-wrap;word-break:break-all;color:#ff5a5a'>{}</pre>{html_tail}", htmlesc(&e))).into_response()
        }
        Ok(login) => {
            let email_from_api = {
                let http = reqwest::Client::builder()
                    .no_proxy()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .ok();
                if let Some(http) = http {
                    api_deezer_get(&http, "/user/me", &login.access_token, &[])
                        .await
                        .ok()
                        .and_then(|v| v.get("email").and_then(|x| x.as_str()).map(|s| s.to_string()))
                } else {
                    None
                }
            };

            let mut map = state.pair.write().await;
            if let Some(s) = map.get_mut(&code) {
                s.arl = login.arl.clone();
                s.token = if login.token.is_empty() {
                    None
                } else {
                    Some(login.token.clone())
                };
                s.access_token = Some(login.access_token.clone());
                if !login.uid.is_empty() {
                    s.user_id = Some(login.uid.clone());
                }
                s.email = email_from_api.or(Some(email));
                s.error = None;
            }
            drop(map);
            pair_store_save(&state).await;
            if let Some(ref arl) = login.arl {
                store_arl_session(&state, arl, &login.token, &login.license_token).await;
                state.api_by_arl.write().await.remove(arl);
            }
            let msg = if login.arl.is_some() {
                "<h3>Готово ✓</h3><p class='muted'>Вернись на ТВ — плагин подключится автоматически.</p>"
            } else {
                "<h3>Вход выполнен</h3><p class='muted'>Библиотека доступна. ARL не получен — полные треки могут не работать, попробуй кнопку «Войти через Deezer».</p>"
            };
            Html(format!("{html_head}{msg}{html_tail}")).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct OauthMeReq {
    access_token: String,
}

async fn oauth_me(Json(req): Json<OauthMeReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    if token.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token required");
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();
    match api_deezer_get(&client, "/user/me", &token, &[]).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

#[derive(Debug, Deserialize)]
struct OauthPlaylistsReq {
    access_token: String,
    index: Option<u32>,
    limit: Option<u32>,
}

async fn oauth_playlists(Json(req): Json<OauthPlaylistsReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    if token.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token required");
    }
    let index = req.index.unwrap_or(0).to_string();
    let limit = req.limit.unwrap_or(50).to_string();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();
    let me = match api_deezer_get(&client, "/user/me", &token, &[]).await {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let uid = me.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
    if uid <= 0 {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "api:no_user_id");
    }
    let path = format!("/user/{uid}/playlists");
    let extra = [("index", index), ("limit", limit)];
    match api_deezer_get(&client, &path, &token, &extra).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

#[derive(Debug, Deserialize)]
struct OauthPlaylistTracksReq {
    access_token: String,
    playlist_id: u64,
    index: Option<u32>,
    limit: Option<u32>,
}

async fn oauth_playlist_tracks(Json(req): Json<OauthPlaylistTracksReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    if token.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token required");
    }
    if req.playlist_id == 0 {
        return json_error(StatusCode::BAD_REQUEST, "playlist_id required");
    }
    let index = req.index.unwrap_or(0).to_string();
    let limit = req.limit.unwrap_or(100).to_string();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();
    let path = format!("/playlist/{}/tracks", req.playlist_id);
    let extra = [("index", index), ("limit", limit)];
    match api_deezer_get(&client, &path, &token, &extra).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

#[derive(Debug, Deserialize)]
struct OauthArlReq {
    access_token: String,
}

async fn oauth_arl(State(state): State<AppState>, Json(req): Json<OauthArlReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    if token.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token required");
    }

    let jar = Arc::new(Jar::default());
    let url_deezer = "https://www.deezer.com".parse::<Url>().unwrap();
    jar.add_cookie_str("comeback=1; Domain=.deezer.com", &url_deezer);
    jar.add_cookie_str("dzr_uniq_id=; Domain=.deezer.com", &url_deezer);
    let client = reqwest::Client::builder()
        .no_proxy()
        .cookie_provider(jar.clone())
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap();

    let _ = client
        .get("https://www.deezer.com/")
        .header(ACCEPT, "*/*")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("User-Agent", gw_browser_ua())
        .send()
        .await;

    if let Err(e) = ensure_anonymous_sid(&client, &jar).await {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, format!("oauth_arl:{e}"));
    }

    establish_oauth_session(&client, &jar, &token).await;

    let uid = api_deezer_get(&client, "/user/me", &token, &[])
        .await
        .ok()
        .and_then(|v| v.get("id").and_then(|x| x.as_i64()))
        .filter(|id| *id > 0)
        .map(|id| id.to_string());

    match gw_fetch_arl(&client, "", "", uid.as_deref()).await {
        Ok((arl, check_form, _, license_token)) if arl.len() >= 20 => {
            store_arl_session(&state, &arl, &check_form, &license_token).await;
            state.api_by_arl.write().await.remove(&arl);
            (StatusCode::OK, Json(json!({ "arl": arl }))).into_response()
        }
        Ok((arl, _, _, _)) => {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("oauth_arl:arl_too_short:{}", arl.len()),
            )
        }
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, format!("oauth_arl:{e}")),
    }
}

#[derive(Debug, Deserialize)]
struct GwPageReq {
    arl: String,
    token: Option<String>,
    user_id: Option<String>,
    page: Option<String>,
    lang: Option<String>,
}

async fn gw_page(Json(req): Json<GwPageReq>) -> impl IntoResponse {
    let arl = req.arl.trim().to_string();
    if arl.len() < 20 {
        return json_error(StatusCode::BAD_REQUEST, "arl required");
    }
    let page = req.page.unwrap_or_else(|| "home".to_string()).trim().to_string();
    if page.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "page required");
    }
    let lang = req
        .lang
        .unwrap_or_else(|| "en".to_string())
        .trim()
        .to_string();
    let lang = if lang.is_empty() { "en".to_string() } else { lang };

    let jar = Arc::new(Jar::default());
    let url_deezer = "https://www.deezer.com".parse::<Url>().unwrap();
    jar.add_cookie_str("comeback=1; Domain=.deezer.com", &url_deezer);
    jar.add_cookie_str(&format!("arl={arl}; Domain=.deezer.com; Path=/"), &url_deezer);

    let client = reqwest::Client::builder()
        .no_proxy()
        .cookie_provider(jar.clone())
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap();

    let ud = match gw_light_call_custom(
        &client,
        "deezer.getUserData",
        "null",
        None,
        &json!({}),
        None,
        true,
        Some(&lang),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::UNAUTHORIZED, format!("gw:getUserData:{e}")),
    };

    let token = req
        .token
        .unwrap_or_default()
        .trim()
        .to_string()
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>();
    let api_token = if !token.is_empty() {
        token
    } else {
        ud.get("checkForm")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    if api_token.is_empty() {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "gw:no_checkForm");
    }

    let user_id = req
        .user_id
        .unwrap_or_default()
        .trim()
        .to_string()
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>();
    let user_id = if !user_id.is_empty() {
        Some(user_id)
    } else {
        ud.get("USER")
            .and_then(|u| u.get("USER_ID"))
            .and_then(|x| x.as_i64())
            .filter(|n| *n > 0)
            .map(|n| n.to_string())
    };

    let support = json!({
        "ads": [],
        "deeplink-list": ["deeplink"],
        "event-card": ["live-event"],
        "grid-preview-one": ["album","artist","artistLineUp","channel","livestream","flow","playlist","radio","show","smarttracklist","track","user","video-link","external-link"],
        "grid-preview-two": ["album","artist","artistLineUp","channel","livestream","flow","playlist","radio","show","smarttracklist","track","user","video-link","external-link"],
        "grid": ["album","artist","artistLineUp","channel","livestream","flow","playlist","radio","show","smarttracklist","track","user","video-link","external-link"],
        "horizontal-grid": ["album","artist","artistLineUp","channel","livestream","flow","playlist","radio","show","smarttracklist","track","user","video-link","external-link"],
        "horizontal-list": ["track","song"],
        "item-highlight": ["radio"],
        "large-card": ["album","external-link","playlist","show","video-link"],
        "list": ["episode"],
        "mini-banner": ["external-link"],
        "slideshow": ["album","artist","channel","external-link","flow","livestream","playlist","show","smarttracklist","user","video-link"],
        "small-horizontal-grid": ["flow"],
        "long-card-horizontal-grid": ["album","artist","artistLineUp","channel","livestream","flow","playlist","radio","show","smarttracklist","track","user","video-link","external-link"],
        "filterable-grid": ["flow"]
    });

    let gateway_input = json!({
        "PAGE": page,
        "VERSION": "2.5",
        "SUPPORT": support,
        "LANG": lang,
        "OPTIONS": ["deeplink_newsandentertainment", "deeplink_subscribeoffer"]
    })
    .to_string();

    let results = match gw_light_call_custom(
        &client,
        "page.get",
        &api_token,
        Some(&gateway_input),
        &json!({}),
        user_id.as_deref(),
        false,
        Some(&lang),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, format!("gw:page.get:{e}")),
    };

    (StatusCode::OK, Json(json!({ "results": results }))).into_response()
}

#[derive(Debug, Deserialize)]
struct GwFlowReq {
    arl: String,
    token: Option<String>,
    user_id: String,
    config_id: Option<String>,
}

async fn gw_flow(Json(req): Json<GwFlowReq>) -> impl IntoResponse {
    let arl = req.arl.trim().to_string();
    if arl.len() < 20 {
        return json_error(StatusCode::BAD_REQUEST, "arl required");
    }
    let user_id = req.user_id.trim().to_string();
    if user_id.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "user_id required");
    }

    let jar = Arc::new(Jar::default());
    let url_deezer = "https://www.deezer.com".parse::<Url>().unwrap();
    jar.add_cookie_str("comeback=1; Domain=.deezer.com", &url_deezer);
    jar.add_cookie_str(&format!("arl={arl}; Domain=.deezer.com; Path=/"), &url_deezer);

    let client = reqwest::Client::builder()
        .no_proxy()
        .cookie_provider(jar.clone())
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap();

    let ud = match gw_light_call_custom(
        &client,
        "deezer.getUserData",
        "null",
        None,
        &json!({}),
        None,
        true,
        None,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::UNAUTHORIZED, format!("gw:getUserData:{e}")),
    };

    // Ignore the token passed from frontend because it might be stale.
    // Always use the freshly fetched checkForm from getUserData.
    let api_token = ud.get("checkForm")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    if api_token.is_empty() {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "gw:no_checkForm");
    }

    let mut params = json!({ "user_id": user_id });
    let config_id = req.config_id.unwrap_or_default().trim().to_string();
    if !config_id.is_empty() && config_id != "default" {
        if let Some(obj) = params.as_object_mut() {
            obj.insert("config_id".to_string(), serde_json::Value::String(config_id));
        }
    }

    let results = match gw_light_call_custom(
        &client,
        "radio.getUserRadio",
        &api_token,
        None,
        &params,
        Some(req.user_id.as_str()),
        false,
        None,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, format!("gw:radio.getUserRadio:{e}")),
    };

    (StatusCode::OK, Json(json!({ "results": results }))).into_response()
}

#[derive(Debug, Deserialize)]
struct OauthFlowReq {
    access_token: String,
    limit: Option<u32>,
}

async fn oauth_flow(Json(req): Json<OauthFlowReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    if token.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token required");
    }
    let limit = req.limit.unwrap_or(40).clamp(1, 100).to_string();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let me = match api_deezer_get(&client, "/user/me", &token, &[]).await {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let uid = me.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
    if uid <= 0 {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "api:no_user_id");
    }

    let path = format!("/user/{uid}/flow");
    let extra = [("limit", limit)];
    match api_deezer_get(&client, &path, &token, &extra).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

#[derive(Debug, Deserialize)]
struct OauthActionReq {
    access_token: String,
    track_id: Option<String>,
    playlist_id: Option<String>,
    title: Option<String>,
}

async fn oauth_favorite_add(Json(req): Json<OauthActionReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    let track_id = req.track_id.unwrap_or_default().trim().to_string();
    if token.is_empty() || track_id.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token and track_id required");
    }
    let client = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(15)).build().unwrap();
    let me = match api_deezer_get(&client, "/user/me", &token, &[]).await {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let uid = me.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
    
    let path = format!("/user/{uid}/tracks");
    match api_deezer_post(&client, &path, &token, &[("track_id", track_id)]).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

async fn oauth_favorite_remove(Json(req): Json<OauthActionReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    let track_id = req.track_id.unwrap_or_default().trim().to_string();
    if token.is_empty() || track_id.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token and track_id required");
    }
    let client = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(15)).build().unwrap();
    let me = match api_deezer_get(&client, "/user/me", &token, &[]).await {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let uid = me.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
    
    let path = format!("/user/{uid}/tracks");
    match api_deezer_delete(&client, &path, &token, &[("track_id", track_id)]).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

async fn oauth_playlist_add(Json(req): Json<OauthActionReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    let track_id = req.track_id.unwrap_or_default().trim().to_string();
    let playlist_id = req.playlist_id.unwrap_or_default().trim().to_string();
    if token.is_empty() || track_id.is_empty() || playlist_id.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token, track_id, playlist_id required");
    }
    let client = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(15)).build().unwrap();
    let path = format!("/playlist/{playlist_id}/tracks");
    match api_deezer_post(&client, &path, &token, &[("songs", track_id)]).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}


async fn oauth_playlist_remove_track(Json(req): Json<OauthActionReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    let track_id = req.track_id.unwrap_or_default().trim().to_string();
    let playlist_id = req.playlist_id.unwrap_or_default().trim().to_string();
    if token.is_empty() || track_id.is_empty() || playlist_id.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token, track_id, playlist_id required");
    }
    let client = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(15)).build().unwrap();
    let path = format!("/playlist/{playlist_id}/tracks");
    match api_deezer_delete(&client, &path, &token, &[("songs", track_id)]).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

async fn oauth_playlist_create(Json(req): Json<OauthActionReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    let title = req.title.unwrap_or_default().trim().to_string();
    if token.is_empty() || title.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token and title required");
    }
    let client = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(15)).build().unwrap();
    let me = match api_deezer_get(&client, "/user/me", &token, &[]).await {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let uid = me.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
    
    let path = format!("/user/{uid}/playlists");
    match api_deezer_post(&client, &path, &token, &[("title", title)]).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

async fn oauth_playlist_update(Json(req): Json<OauthActionReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    let title = req.title.unwrap_or_default().trim().to_string();
    let playlist_id = req.playlist_id.unwrap_or_default().trim().to_string();
    if token.is_empty() || title.is_empty() || playlist_id.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token, title, playlist_id required");
    }
    let client = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(15)).build().unwrap();
    let path = format!("/playlist/{playlist_id}");
    match api_deezer_post(&client, &path, &token, &[("title", title)]).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

async fn oauth_playlist_delete(Json(req): Json<OauthActionReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    let playlist_id = req.playlist_id.unwrap_or_default().trim().to_string();
    if token.is_empty() || playlist_id.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token and playlist_id required");
    }
    let client = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(15)).build().unwrap();
    let path = format!("/playlist/{playlist_id}");
    match api_deezer_delete(&client, &path, &token, &[]).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

#[derive(Debug, Deserialize)]
struct OauthRecoReq {
    access_token: String,
    index: Option<u32>,
    limit: Option<u32>,
}

async fn oauth_reco_playlists(Json(req): Json<OauthRecoReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    if token.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token required");
    }
    let index = req.index.unwrap_or(0).to_string();
    let limit = req.limit.unwrap_or(20).clamp(1, 50).to_string();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let me = match api_deezer_get(&client, "/user/me", &token, &[]).await {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let uid = me.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
    if uid <= 0 {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "api:no_user_id");
    }
    let path = format!("/user/{uid}/recommendations/playlists");
    let extra = [("index", index), ("limit", limit)];
    match api_deezer_get(&client, &path, &token, &extra).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

async fn oauth_reco_albums(Json(req): Json<OauthRecoReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    if token.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token required");
    }
    let index = req.index.unwrap_or(0).to_string();
    let limit = req.limit.unwrap_or(20).clamp(1, 50).to_string();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let me = match api_deezer_get(&client, "/user/me", &token, &[]).await {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let uid = me.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
    if uid <= 0 {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "api:no_user_id");
    }
    let path = format!("/user/{uid}/recommendations/albums");
    let extra = [("index", index), ("limit", limit)];
    match api_deezer_get(&client, &path, &token, &extra).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

async fn oauth_reco_artists(Json(req): Json<OauthRecoReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    if token.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token required");
    }
    let index = req.index.unwrap_or(0).to_string();
    let limit = req.limit.unwrap_or(20).clamp(1, 50).to_string();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let me = match api_deezer_get(&client, "/user/me", &token, &[]).await {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let uid = me.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
    if uid <= 0 {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "api:no_user_id");
    }
    let path = format!("/user/{uid}/recommendations/artists");
    let extra = [("index", index), ("limit", limit)];
    match api_deezer_get(&client, &path, &token, &extra).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

async fn oauth_reco_tracks(Json(req): Json<OauthRecoReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    if token.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token required");
    }
    let index = req.index.unwrap_or(0).to_string();
    let limit = req.limit.unwrap_or(40).clamp(1, 100).to_string();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let me = match api_deezer_get(&client, "/user/me", &token, &[]).await {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let uid = me.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
    if uid <= 0 {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "api:no_user_id");
    }
    let path = format!("/user/{uid}/recommendations/tracks");
    let extra = [("index", index), ("limit", limit)];
    match api_deezer_get(&client, &path, &token, &extra).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

#[derive(Debug, Deserialize)]
struct OauthHistoryReq {
    access_token: String,
    index: Option<u32>,
    limit: Option<u32>,
}

async fn oauth_history(Json(req): Json<OauthHistoryReq>) -> impl IntoResponse {
    let token = req.access_token.trim().to_string();
    if token.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "access_token required");
    }
    let index = req.index.unwrap_or(0).to_string();
    let limit = req.limit.unwrap_or(50).clamp(1, 100).to_string();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let me = match api_deezer_get(&client, "/user/me", &token, &[]).await {
        Ok(v) => v,
        Err(e) => return json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let uid = me.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
    if uid <= 0 {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "api:no_user_id");
    }
    let path = format!("/user/{uid}/history");
    let extra = [("index", index), ("limit", limit)];
    match api_deezer_get(&client, &path, &token, &extra).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

#[derive(Debug, Deserialize)]
struct WarmArlReq {
    arl: String,
}

async fn warm_arl(State(state): State<AppState>, Json(req): Json<WarmArlReq>) -> impl IntoResponse {
    let arl = req.arl.trim().to_string();
    if arl.len() < 20 {
        return json_error(StatusCode::BAD_REQUEST, "arl required");
    }

    state.api_by_arl.write().await.remove(&arl);
    let client = api_client_for_arl(&state, Some(arl.clone())).await;
    let session = {
        let mut c = client.lock().await;
        if c.license_token.is_empty() {
            if let Err(e) = c.force_renew().await {
                return json_error(StatusCode::SERVICE_UNAVAILABLE, format!("warm:renew:{e}"));
            }
        }
        c.session_tokens()
    };

    store_arl_session(&state, &arl, &session.0, &session.1).await;
    state.api_by_arl.write().await.remove(&arl);
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

#[tokio::main]
async fn main() {
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or("0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or("7860".to_string());
    let port: u16 = port.parse().unwrap_or(7860);

    let state = AppState {
        api: Arc::new(Mutex::new(APIClient::new())),
        api_by_arl: Arc::new(RwLock::new(HashMap::new())),
        arl_sessions: Arc::new(RwLock::new(HashMap::new())),
        pair: Arc::new(RwLock::new(HashMap::new())),
        pair_store_path: std::env::var("PAIR_STORE_PATH").ok().unwrap_or_else(|| "pair_store.json".to_string()),
        arl_store_path: std::env::var("ARL_STORE_PATH").ok().unwrap_or_else(|| "arl_store.json".to_string()),
        cdn_cache: Arc::new(RwLock::new(HashMap::new())),
    };
    arl_store_load(&state).await;
    pair_store_load(&state).await;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS, Method::HEAD])
        .allow_headers([CONTENT_TYPE]);

    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(root))
        .route("/debug_log", get(debug_log))
        .route("/get_url", post(get_url))
        .route("/fetch", get(fetch))
        .route("/stream", get(stream))
        .route("/download", get(download))
        .route("/send_audio", get(send_audio))
        .route("/warm", get(warm))
        .route("/stream_info", get(stream_info))
        .route("/user_data", post(user_data))
        .route("/playlists", post(playlists))
        .route("/playlist", post(playlist_tracks))
        .route("/login", post(login))
        .route("/pair/start", get(pair_start))
        .route("/pair/status", get(pair_status))
        .route("/pair", get(pair_page))
        .route("/pair/channel", get(pair_channel))
        .route("/pair/oauth", post(pair_oauth))
        .route("/pair/oauth_cb", get(pair_oauth_cb))
        .route("/pair/complete", post(pair_complete))
        .route("/gw/page", post(gw_page))
        .route("/gw/flow", post(gw_flow))
        .route("/oauth/me", post(oauth_me))
        .route("/oauth/playlists", post(oauth_playlists))
        .route("/oauth/playlist_tracks", post(oauth_playlist_tracks))
        .route("/oauth/arl", post(oauth_arl))
        .route("/session/warm", post(warm_arl))
        .route("/oauth/flow", post(oauth_flow))
        .route("/oauth/reco_playlists", post(oauth_reco_playlists))
        .route("/oauth/reco_albums", post(oauth_reco_albums))
        .route("/oauth/reco_artists", post(oauth_reco_artists))
        .route("/oauth/reco_tracks", post(oauth_reco_tracks))
        .route("/oauth/history", post(oauth_history))
        .route("/oauth/favorite_add", post(oauth_favorite_add))
        .route("/oauth/favorite_remove", post(oauth_favorite_remove))
        .route("/oauth/playlist_add", post(oauth_playlist_add))
        .route("/oauth/playlist_remove_track", post(oauth_playlist_remove_track))
        .route("/oauth/playlist_create", post(oauth_playlist_create))
        .route("/oauth/playlist_update", post(oauth_playlist_update))
        .route("/oauth/playlist_delete", post(oauth_playlist_delete))
        .with_state(state)
        .layer(cors)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http());

    let bind_addr = format!("{bind_addr}:{port}");
    println!("Listening on {bind_addr}");

    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();

    axum::serve(listener, app)
        .await
        .unwrap();
}
