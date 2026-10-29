//! HTTP routes: the embedded PWA, `/v1/info`, the pairing endpoints and `/v1/revoke`.
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde_json::json;

use super::assets::{WebAssets, content_type};
use super::conn::PeerInfo;
use super::{Inner, LOG, ServerEvent, ws};
use crate::origin::{require_json_content_type, validate_host, validate_origin};
use crate::pairing::{PairError, PairPoll, PairRequest, PairingId};
use crate::protocol::{
    InfoResponse, PROTOCOL_VERSION, PairRequestBody, PairResponse, RetryAfterBody, SecretString,
    check_version,
};

const POLL_WINDOW: Duration = Duration::from_secs(25);
const POLL_RECHECK: Duration = Duration::from_secs(1);
const MAX_BODY: usize = 4 * 1024;
const MAX_POLL_ID_LEN: usize = 64;

const CSP: &str = "default-src 'self'; script-src 'self'; connect-src 'self' wss:; \
style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; manifest-src 'self'; \
object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

type State_ = State<Arc<Inner>>;

pub(super) fn router(inner: Arc<Inner>) -> Router {
    Router::new()
        .route("/v1/info", get(info))
        .route("/v1/pair", post(pair))
        .route("/v1/pair/{id}", get(pair_poll))
        .route("/v1/revoke", post(revoke))
        .route("/v1/ws", get(ws::upgrade))
        .fallback(static_asset)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(inner.clone(), guard))
        .with_state(inner)
}

fn static_header(name: &'static str, value: &'static str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    )
}

/// Validates `Host` and `Origin` on every request, then stamps security headers on the response.
async fn guard(State(inner): State_, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let one = |name| -> Result<Option<&str>, ()> {
        let mut it = headers.get_all(name).iter();
        match (it.next(), it.next()) {
            (None, _) => Ok(None),
            (Some(v), None) => v.to_str().map(Some).map_err(|_| ()),
            (Some(_), Some(_)) => Err(()),
        }
    };
    let bound = inner.bound_sockets();
    let ok = match (one(header::HOST), one(header::ORIGIN)) {
        (Ok(host), Ok(origin)) => {
            validate_host(host, &bound).is_ok() && validate_origin(origin, &bound).is_ok()
        }
        _ => false,
    };
    let mut resp = if ok {
        next.run(req).await
    } else {
        log::debug!(target: LOG, "rejected request with bad Host/Origin");
        StatusCode::FORBIDDEN.into_response()
    };
    let h = resp.headers_mut();
    for (k, v) in [
        static_header("content-security-policy", CSP),
        static_header("x-frame-options", "DENY"),
        static_header("x-content-type-options", "nosniff"),
        static_header("referrer-policy", "no-referrer"),
        static_header("cross-origin-resource-policy", "same-origin"),
    ] {
        h.insert(k, v);
    }
    resp
}

fn json_response(status: StatusCode, body: impl serde::Serialize) -> Response {
    let mut resp = (status, Json(body)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn too_many(retry_after: u64) -> Response {
    let mut resp = json_response(
        StatusCode::TOO_MANY_REQUESTS,
        RetryAfterBody { retry_after },
    );
    if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

fn unauthorized() -> Response {
    json_response(StatusCode::UNAUTHORIZED, json!({"error": "unauthorized"}))
}

fn bad_request(msg: &str) -> Response {
    json_response(StatusCode::BAD_REQUEST, json!({"error": msg}))
}

fn content_type_ok(headers: &HeaderMap) -> bool {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    require_json_content_type(ct).is_ok()
}

async fn info(State(inner): State_) -> Response {
    let pairing = inner.lock_pairing().is_armed();
    json_response(
        StatusCode::OK,
        InfoResponse {
            protocol: PROTOCOL_VERSION,
            instance: inner.cfg.instance_id.clone(),
            name: inner.cfg.pc_name.clone(),
            pairing,
        },
    )
}

async fn pair(
    State(inner): State_,
    Extension(peer): Extension<PeerInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !content_type_ok(&headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let Ok(req) = serde_json::from_slice::<PairRequestBody>(&body) else {
        return bad_request("malformed request");
    };
    if check_version(req.v).is_err() {
        return bad_request("unsupported protocol version");
    }
    let request = PairRequest {
        device_name: req.device_name,
        platform: req.platform,
        ip: Some(peer.peer.ip()),
    };
    let result = {
        let mut p = inner.lock_pairing();
        p.submit(req.secret.expose(), request).map(|id| {
            let polled = p.poll(&id);
            let pending = p.pending_approvals().into_iter().find(|a| a.id == id);
            (id, polled, pending)
        })
    };
    match result {
        Ok((id, PairPoll::Pending, pending)) => {
            if let Some(pending) = pending {
                inner.emit(ServerEvent::ApprovalRequested(pending));
            }
            json_response(StatusCode::OK, PairResponse::Pending { poll: id.0 })
        }
        Ok((id, polled, _)) => poll_response(&inner, &id, polled),
        Err(err) => match err {
            PairError::Locked { retry_after } | PairError::RateLimited { retry_after } => {
                too_many(retry_after)
            }
            PairError::BadSecret | PairError::NotArmed | PairError::Expired => {
                let until = inner.lock_pairing().locked_until();
                if let Some(until) = until {
                    inner.emit(ServerEvent::LockedOut { until });
                }
                unauthorized()
            }
            PairError::InvalidRequest(msg) => bad_request(msg),
            PairError::Internal(e) => {
                log::error!(target: LOG, "pairing failed: {e}");
                json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "internal error"}),
                )
            }
        },
    }
}

fn poll_response(inner: &Inner, id: &PairingId, polled: PairPoll) -> Response {
    match polled {
        PairPoll::Pending => {
            json_response(StatusCode::OK, PairResponse::Pending { poll: id.0.clone() })
        }
        PairPoll::Approved(device) => {
            inner.emit(ServerEvent::DevicesChanged);
            json_response(
                StatusCode::OK,
                PairResponse::Approved {
                    device_id: device.id.0.clone(),
                    token: SecretString::new(device.token.as_str()),
                },
            )
        }
        PairPoll::Denied => json_response(StatusCode::OK, PairResponse::Denied),
        PairPoll::Expired => json_response(StatusCode::OK, PairResponse::Expired),
    }
}

async fn pair_poll(State(inner): State_, Path(id): Path<String>) -> Response {
    if id.len() > MAX_POLL_ID_LEN {
        return StatusCode::NOT_FOUND.into_response();
    }
    let id = PairingId(id);
    let deadline = tokio::time::Instant::now() + POLL_WINDOW;
    loop {
        let wake = inner.pair_notify.notified();
        tokio::pin!(wake);
        wake.as_mut().enable();
        let polled = inner.lock_pairing().poll(&id);
        if !matches!(polled, PairPoll::Pending) {
            return poll_response(&inner, &id, polled);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return json_response(StatusCode::OK, PairResponse::Pending { poll: id.0 });
        }
        let wait = POLL_RECHECK.min(deadline - now);
        tokio::select! {
            () = &mut wake => {}
            () = tokio::time::sleep(wait) => {}
        }
    }
}

pub(super) fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = v.strip_prefix("Bearer ")?.trim();
    (!token.is_empty() && token.len() <= 256).then_some(token)
}

async fn revoke(
    State(inner): State_,
    Extension(peer): Extension<PeerInfo>,
    headers: HeaderMap,
) -> Response {
    if !content_type_ok(&headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    if let Some(retry_after) = inner.auth_locked_for() {
        return too_many(retry_after);
    }
    let Some(token) = bearer(&headers) else {
        inner.record_auth_failure();
        return unauthorized();
    };
    let device = inner
        .lock_registry()
        .authenticate(token, Some(peer.peer.ip()));
    let Ok(device) = device else {
        inner.record_auth_failure();
        return unauthorized();
    };
    let _ = inner.lock_registry().revoke(&device);
    inner.kill_where("device unpaired itself", |s| s.device_id == device);
    inner.emit(ServerEvent::DevicesChanged);
    json_response(StatusCode::OK, json!({}))
}

async fn static_asset(method: Method, uri: axum::http::Uri, headers: HeaderMap) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = uri.path();
    let key = match path {
        "/" | "/pair" | "/pair/" => "index.html",
        p => p.trim_start_matches('/'),
    };
    if key.is_empty() || key.contains(['\\', '%']) || key.split('/').any(|s| s == ".." || s == ".")
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(file) = WebAssets::get(key) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let etag = format!("\"{}\"", hex::encode(file.metadata.sha256_hash()));
    let is_html = key.ends_with(".html");
    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, content_type(key))
        .header(header::ETAG, &etag)
        .header(
            header::CACHE_CONTROL,
            if is_html { "no-store" } else { "no-cache" },
        );
    let not_modified = !is_html
        && headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == etag);
    let body = if not_modified {
        builder = builder.status(StatusCode::NOT_MODIFIED);
        Body::empty()
    } else {
        Body::from(file.data.into_owned())
    };
    builder
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
