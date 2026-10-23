//! A WebSocket+TLS client based on `async-tungstenite`.

use std::sync::Arc;

use async_tungstenite::WebSocketStream;
use async_tungstenite::tokio::{
    ClientStream, client_async_tls_with_connector_and_config, connect_async_with_tls_connector,
};
use async_tungstenite::tungstenite::client::IntoClientRequest;
use futures::{Sink, Stream};
use futures_util::StreamExt as _;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::WebsocketMessage;

mod proxy;

pub use async_tungstenite::tungstenite::Message;

pub struct WebSocket(WebSocketStream<ClientStream<TcpStream>>);

static CLIENT_CONFIG: std::sync::LazyLock<Result<Arc<rustls::ClientConfig>, rustls::Error>> =
    std::sync::LazyLock::new(|| Ok(Arc::new(rustls::ClientConfig::with_platform_verifier()?)));

/// `host:port` authorities refused by [`connect`] (AnonWarp stub-server catch-all; see
/// `http_client::egress`).
static BLOCKED_AUTHORITIES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

pub fn set_blocked_authorities(authorities: &[&str]) {
    if let Ok(mut blocked) = BLOCKED_AUTHORITIES.lock() {
        *blocked = authorities.iter().map(|a| a.to_ascii_lowercase()).collect();
    }
}

/// Connects to a WebSocket address (optionally secured by TLS).
///
/// When `HTTPS_PROXY`, `HTTP_PROXY`, or `ALL_PROXY` environment variables are set,
/// the connection is tunneled through the specified HTTP proxy using the CONNECT method.
/// The `NO_PROXY` environment variable is respected to bypass the proxy for specific hosts.
pub async fn connect(request: impl IntoClientRequest + Unpin) -> anyhow::Result<WebSocket> {
    let request = request.into_client_request()?;
    if let (Some(host), Some(port)) = (
        request.uri().host(),
        request
            .uri()
            .port_u16()
            .or_else(|| match request.uri().scheme_str() {
                Some("wss") => Some(443),
                Some("ws") => Some(80),
                _ => None,
            }),
    ) && BLOCKED_AUTHORITIES
        .lock()
        .is_ok_and(|blocked| blocked.contains(&format!("{}:{port}", host.to_ascii_lowercase())))
    {
        log::debug!(
            "websocket egress guard: blocked connection to {}",
            request.uri()
        );
        anyhow::bail!(
            "websocket connection to {} blocked (stub server mode)",
            request.uri()
        );
    }
    let tls_connector = Some(TlsConnector::from(CLIENT_CONFIG.clone()?));

    if let Some(proxy_info) = proxy::resolve_proxy(request.uri())? {
        log::debug!(
            "Using HTTP proxy {}:{} for WebSocket connection to {}",
            proxy_info.host,
            proxy_info.port,
            request.uri(),
        );
        let tcp_stream = proxy::connect_via_proxy(&proxy_info, request.uri()).await?;
        let (stream, _response) =
            client_async_tls_with_connector_and_config(request, tcp_stream, tls_connector, None)
                .await?;
        Ok(WebSocket(stream))
    } else {
        let stream = connect_async_with_tls_connector(request, tls_connector)
            .await?
            .0;
        Ok(WebSocket(stream))
    }
}

impl WebSocket {
    pub async fn split(
        self,
    ) -> (
        impl Sink<Message, Error = Error>,
        impl Stream<Item = Result<Message, Error>>,
    ) {
        self.0.split()
    }

    pub async fn into_graphql_client_builder(self) -> graphql_ws_client::ClientBuilder {
        graphql_ws_client::Client::build(self.0)
    }
}

pub type Error = async_tungstenite::tungstenite::Error;

impl WebsocketMessage for Message {
    fn new_binary(bytes: Vec<u8>) -> Self {
        Self::Binary(bytes)
    }

    fn binary(&self) -> Option<&[u8]> {
        match self {
            Message::Binary(bytes) => Some(bytes.as_ref()),
            _ => None,
        }
    }

    fn new_text(text: String) -> Self {
        Self::Text(text)
    }

    fn new(text: String) -> Self {
        Self::new_text(text)
    }

    fn text(&self) -> Option<&str> {
        match self {
            Message::Text(text) => Some(text),
            _ => None,
        }
    }
}
