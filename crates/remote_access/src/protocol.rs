//! `anonwarp-remote` v1 wire types (REMOTE_CONTROL.md section 7).
//!
//! * Text WebSocket frames are JSON control messages tagged by `"t"`.
//! * Binary frames carry PTY bytes: `[kind u8][stream u32 BE]` then, for output
//!   only, `[offset u64 BE]`, then the payload.
//!
//! Unknown JSON fields are ignored in both directions (forward compatibility).
//! Unknown `t` values are reported as [`ParseError::UnknownType`] so the server
//! can answer `error code=unknown_type` without closing the connection.
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::host::{PaneId, TreeSnapshot};

pub const PROTOCOL_VERSION: u32 = 1;
/// Minimum protocol version still served (N-1 rule; v1 has no predecessor).
pub const MIN_PROTOCOL_VERSION: u32 = 1;
pub const WS_SUBPROTOCOL: &str = "anonwarp.v1";
pub const DEFAULT_PORT_BASE: u16 = 9477;

pub const MAX_TEXT_FRAME: usize = 64 * 1024;
pub const MAX_BINARY_FRAME: usize = 256 * 1024;
pub const MAX_INPUT_PAYLOAD: usize = 64 * 1024;
pub const OUTPUT_HEADER_LEN: usize = 1 + 4 + 8;
pub const INPUT_HEADER_LEN: usize = 1 + 4;
/// Largest output payload that keeps the whole frame within `MAX_BINARY_FRAME`.
pub const MAX_OUTPUT_PAYLOAD: usize = MAX_BINARY_FRAME - OUTPUT_HEADER_LEN;

pub const HELLO_DEADLINE_SECS: u64 = 3;
pub const SERVER_PING_INTERVAL_SECS: u64 = 15;
pub const SILENCE_TIMEOUT_SECS: u64 = 45;
/// Client acks output offsets at least this often (bytes).
pub const ACK_INTERVAL_BYTES: u64 = 256 * 1024;
/// Server stops reading the mirror queue when `sent - acked` exceeds this.
pub const BACKPRESSURE_HIGH_BYTES: u64 = 1024 * 1024;
/// Per-client queue cap before dropping it and re-sending a snapshot.
pub const QUEUE_DROP_BYTES: u64 = 4 * 1024 * 1024;
pub const INPUT_RATE_BYTES_PER_SEC: u64 = 1024 * 1024;
pub const INPUT_BURST_BYTES: u64 = 256 * 1024;
pub const MAX_AUTHENTICATED_SOCKETS: usize = 4;
pub const MAX_UNAUTHENTICATED_SOCKETS: usize = 8;

/// WebSocket close codes.
pub mod close_code {
    pub const BAD_REQUEST: u16 = 4400;
    pub const AUTH_FAILED: u16 = 4401;
    pub const KILLED: u16 = 4403;
    pub const IDLE: u16 = 4408;
    pub const RATE_LIMITED: u16 = 4429;
}

/// Values for `error.code`.
pub mod error_code {
    pub const UNSUPPORTED_VERSION: &str = "unsupported_version";
    pub const UNKNOWN_TYPE: &str = "unknown_type";
    pub const BAD_REQUEST: &str = "bad_request";
    pub const RESIZE_DENIED: &str = "resize_denied";
    pub const NOT_FOUND: &str = "not_found";
    pub const NOT_ATTACHED: &str = "not_attached";
    pub const TOO_LARGE: &str = "too_large";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const HOST_ERROR: &str = "host_error";
}

/// A string that never prints itself (tokens, pairing secrets).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// HTTP bodies
// ---------------------------------------------------------------------------

/// `GET /v1/info`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfoResponse {
    pub protocol: u32,
    pub instance: String,
    pub name: String,
    pub pairing: bool,
}

/// `POST /v1/pair` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequestBody {
    pub v: u32,
    pub secret: SecretString,
    pub device_name: String,
    pub platform: String,
}

/// `POST /v1/pair` and `GET /v1/pair/<id>` responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PairResponse {
    Pending {
        poll: String,
    },
    Approved {
        device_id: String,
        token: SecretString,
    },
    Denied,
    Expired,
}

/// `429` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryAfterBody {
    pub retry_after: u64,
}

// ---------------------------------------------------------------------------
// Control messages
// ---------------------------------------------------------------------------

/// Client -> server JSON control frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ClientMsg {
    Hello {
        v: u32,
        token: SecretString,
        client: String,
        #[serde(default)]
        caps: Vec<String>,
    },
    List {},
    Attach {
        pane: PaneId,
        stream: u32,
        #[serde(default = "default_true")]
        replay: bool,
    },
    Detach {
        stream: u32,
    },
    /// Debug/text alternative to binary input frames.
    Input {
        stream: u32,
        text_b64: String,
    },
    Resize {
        stream: u32,
        cols: u16,
        rows: u16,
    },
    Action {
        id: u64,
        name: String,
        #[serde(default)]
        target: serde_json::Value,
        #[serde(default)]
        params: serde_json::Value,
    },
    Ping {
        n: u64,
    },
    Ack {
        stream: u32,
        offset: u64,
    },
}

const CLIENT_TYPES: &[&str] = &[
    "hello", "list", "attach", "detach", "input", "resize", "action", "ping", "ack",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_text_frame: usize,
    pub max_binary_frame: usize,
    pub max_input: usize,
    pub ack_interval: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_text_frame: MAX_TEXT_FRAME,
            max_binary_frame: MAX_BINARY_FRAME,
            max_input: MAX_INPUT_PAYLOAD,
            ack_interval: ACK_INTERVAL_BYTES,
        }
    }
}

/// Server -> client JSON control frames.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ServerMsg {
    Welcome {
        v: u32,
        device: String,
        server: String,
        limits: Limits,
        phone_resize: bool,
    },
    Tree(TreeSnapshot),
    TreeChanged {},
    /// Precedes the binary frames (`ESC c`, ring contents, live data) for `stream`.
    Snapshot {
        stream: u32,
        pane: PaneId,
        cols: u16,
        rows: u16,
        alt_screen: bool,
        offset: u64,
        #[serde(default)]
        lagged: bool,
    },
    PaneState {
        pane: PaneId,
        alt_screen: bool,
        command_running: bool,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        title: Option<String>,
    },
    PaneClosed {
        pane: PaneId,
    },
    SessionKilled {
        reason: String,
    },
    Error {
        code: String,
        message: String,
    },
    Pong {
        n: u64,
    },
    /// Reply to `action`.
    Result {
        id: u64,
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<ActionError>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionError {
    pub code: String,
    pub message: String,
}

impl ServerMsg {
    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self::Error {
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub fn action_ok(id: u64, data: serde_json::Value) -> Self {
        Self::Result {
            id,
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn action_err(id: u64, code: &str, message: impl Into<String>) -> Self {
        Self::Result {
            id,
            ok: false,
            data: None,
            error: Some(ActionError {
                code: code.to_string(),
                message: message.into(),
            }),
        }
    }

    pub fn to_text(&self) -> String {
        // Serialization of these types cannot fail (no maps with non-string keys).
        serde_json::to_string(self)
            .unwrap_or_else(|_| "{\"t\":\"error\",\"code\":\"internal\",\"message\":\"\"}".into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("text frame exceeds {MAX_TEXT_FRAME} bytes")]
    TooLarge,
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("unknown message type `{0}`")]
    UnknownType(String),
}

impl ParseError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::TooLarge => error_code::TOO_LARGE,
            Self::Malformed(_) => error_code::BAD_REQUEST,
            Self::UnknownType(_) => error_code::UNKNOWN_TYPE,
        }
    }
}

/// Parses a client text frame, distinguishing unknown types (recoverable) from
/// malformed messages.
pub fn parse_client_text(text: &str) -> Result<ClientMsg, ParseError> {
    if text.len() > MAX_TEXT_FRAME {
        return Err(ParseError::TooLarge);
    }
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| ParseError::Malformed(e.to_string()))?;
    let t = value
        .get("t")
        .and_then(|t| t.as_str())
        .ok_or_else(|| ParseError::Malformed("missing `t`".into()))?
        .to_string();
    if !CLIENT_TYPES.contains(&t.as_str()) {
        return Err(ParseError::UnknownType(t));
    }
    serde_json::from_value(value).map_err(|e| ParseError::Malformed(e.to_string()))
}

/// Decides whether the client's `hello.v` can be served.
pub fn check_version(v: u32) -> Result<(), ServerMsg> {
    if (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&v) {
        Ok(())
    } else {
        Err(ServerMsg::error(
            error_code::UNSUPPORTED_VERSION,
            format!("server supports protocol {MIN_PROTOCOL_VERSION}..={PROTOCOL_VERSION}"),
        ))
    }
}

// ---------------------------------------------------------------------------
// Binary frames
// ---------------------------------------------------------------------------

pub const FRAME_OUTPUT: u8 = 0x01;
pub const FRAME_INPUT: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryFrame<'a> {
    Output {
        stream: u32,
        offset: u64,
        payload: &'a [u8],
    },
    Input {
        stream: u32,
        payload: &'a [u8],
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("frame too short")]
    Short,
    #[error("frame too large")]
    TooLarge,
    #[error("unknown frame kind {0:#04x}")]
    UnknownKind(u8),
}

/// Encodes an output frame. The payload must fit `MAX_OUTPUT_PAYLOAD`; callers
/// chunk with [`chunk_output`].
pub fn encode_output_frame(
    stream: u32,
    offset: u64,
    payload: &[u8],
) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_OUTPUT_PAYLOAD {
        return Err(FrameError::TooLarge);
    }
    let mut out = Vec::with_capacity(OUTPUT_HEADER_LEN + payload.len());
    out.push(FRAME_OUTPUT);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn encode_input_frame(stream: u32, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_INPUT_PAYLOAD {
        return Err(FrameError::TooLarge);
    }
    let mut out = Vec::with_capacity(INPUT_HEADER_LEN + payload.len());
    out.push(FRAME_INPUT);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decodes a binary frame, enforcing the size caps.
pub fn decode_binary_frame(frame: &[u8]) -> Result<BinaryFrame<'_>, FrameError> {
    if frame.len() > MAX_BINARY_FRAME {
        return Err(FrameError::TooLarge);
    }
    let (&kind, rest) = frame.split_first().ok_or(FrameError::Short)?;
    let stream = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    match kind {
        FRAME_OUTPUT => {
            if rest.len() < 12 {
                return Err(FrameError::Short);
            }
            let mut off = [0u8; 8];
            off.copy_from_slice(&rest[4..12]);
            Ok(BinaryFrame::Output {
                stream: stream(rest),
                offset: u64::from_be_bytes(off),
                payload: &rest[12..],
            })
        }
        FRAME_INPUT => {
            if rest.len() < 4 {
                return Err(FrameError::Short);
            }
            let payload = &rest[4..];
            if payload.len() > MAX_INPUT_PAYLOAD {
                return Err(FrameError::TooLarge);
            }
            Ok(BinaryFrame::Input {
                stream: stream(rest),
                payload,
            })
        }
        k => Err(FrameError::UnknownKind(k)),
    }
}

/// Splits `data` starting at stream `offset` into `(offset, chunk)` pieces that
/// each fit one output frame.
pub fn chunk_output(offset: u64, data: &[u8]) -> impl Iterator<Item = (u64, &[u8])> {
    data.chunks(MAX_OUTPUT_PAYLOAD).scan(offset, |off, c| {
        let o = *off;
        *off += c.len() as u64;
        Some((o, c))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{PaneNode, TabNode, WindowNode};
    use serde_json::json;

    #[test]
    fn hello_fixture() {
        let m = parse_client_text(
            r#"{"t":"hello","v":1,"token":"abc","client":"web","caps":["binary","resnap"],"future":1}"#,
        )
        .unwrap();
        assert_eq!(
            m,
            ClientMsg::Hello {
                v: 1,
                token: SecretString::new("abc"),
                client: "web".into(),
                caps: vec!["binary".into(), "resnap".into()],
            }
        );
        assert!(!format!("{m:?}").contains("abc"));
    }

    #[test]
    fn client_fixtures() {
        assert_eq!(
            parse_client_text(r#"{"t":"list"}"#).unwrap(),
            ClientMsg::List {}
        );
        assert_eq!(
            parse_client_text(r#"{"t":"attach","pane":"p1","stream":1}"#).unwrap(),
            ClientMsg::Attach {
                pane: PaneId("p1".into()),
                stream: 1,
                replay: true
            }
        );
        assert_eq!(
            parse_client_text(r#"{"t":"attach","pane":"p1","stream":2,"replay":false}"#).unwrap(),
            ClientMsg::Attach {
                pane: PaneId("p1".into()),
                stream: 2,
                replay: false
            }
        );
        assert_eq!(
            parse_client_text(r#"{"t":"detach","stream":1}"#).unwrap(),
            ClientMsg::Detach { stream: 1 }
        );
        assert_eq!(
            parse_client_text(r#"{"t":"input","stream":1,"text_b64":"bHMK"}"#).unwrap(),
            ClientMsg::Input {
                stream: 1,
                text_b64: "bHMK".into()
            }
        );
        assert_eq!(
            parse_client_text(r#"{"t":"resize","stream":1,"cols":80,"rows":24}"#).unwrap(),
            ClientMsg::Resize {
                stream: 1,
                cols: 80,
                rows: 24
            }
        );
        assert_eq!(
            parse_client_text(r#"{"t":"action","id":7,"name":"tab.create"}"#).unwrap(),
            ClientMsg::Action {
                id: 7,
                name: "tab.create".into(),
                target: serde_json::Value::Null,
                params: serde_json::Value::Null
            }
        );
        assert_eq!(
            parse_client_text(r#"{"t":"ping","n":3}"#).unwrap(),
            ClientMsg::Ping { n: 3 }
        );
        assert_eq!(
            parse_client_text(r#"{"t":"ack","stream":1,"offset":262144}"#).unwrap(),
            ClientMsg::Ack {
                stream: 1,
                offset: 262144
            }
        );
    }

    #[test]
    fn client_msg_round_trip() {
        let msgs = vec![
            ClientMsg::Hello {
                v: 1,
                token: SecretString::new("t"),
                client: "android".into(),
                caps: vec![],
            },
            ClientMsg::List {},
            ClientMsg::Action {
                id: 1,
                name: "pane.split".into(),
                target: json!({"pane":"p"}),
                params: json!({"dir":"right"}),
            },
        ];
        for m in msgs {
            let s = serde_json::to_string(&m).unwrap();
            assert_eq!(parse_client_text(&s).unwrap(), m);
        }
    }

    #[test]
    fn parse_errors() {
        assert!(matches!(
            parse_client_text("nope"),
            Err(ParseError::Malformed(_))
        ));
        assert!(matches!(
            parse_client_text("[]"),
            Err(ParseError::Malformed(_))
        ));
        assert!(matches!(
            parse_client_text(r#"{"v":1}"#),
            Err(ParseError::Malformed(_))
        ));
        assert!(matches!(
            parse_client_text(r#"{"t":5}"#),
            Err(ParseError::Malformed(_))
        ));
        assert_eq!(
            parse_client_text(r#"{"t":"teleport"}"#),
            Err(ParseError::UnknownType("teleport".into()))
        );
        // Known type, wrong shape.
        assert!(matches!(
            parse_client_text(r#"{"t":"attach","pane":"p"}"#),
            Err(ParseError::Malformed(_))
        ));
        assert!(matches!(
            parse_client_text(r#"{"t":"resize","stream":1,"cols":-1,"rows":2}"#),
            Err(ParseError::Malformed(_))
        ));
        assert!(matches!(
            parse_client_text(r#"{"t":"resize","stream":1,"cols":70000,"rows":2}"#),
            Err(ParseError::Malformed(_))
        ));
        let big = format!(
            r#"{{"t":"ping","n":1,"pad":"{}"}}"#,
            "x".repeat(MAX_TEXT_FRAME)
        );
        assert_eq!(parse_client_text(&big), Err(ParseError::TooLarge));
        assert_eq!(ParseError::TooLarge.error_code(), "too_large");
        assert_eq!(
            ParseError::UnknownType("x".into()).error_code(),
            "unknown_type"
        );
    }

    #[test]
    fn server_fixtures() {
        let welcome = ServerMsg::Welcome {
            v: 1,
            device: "d1".into(),
            server: "anonwarp 0.1".into(),
            limits: Limits::default(),
            phone_resize: false,
        };
        let v: serde_json::Value = serde_json::from_str(&welcome.to_text()).unwrap();
        assert_eq!(v["t"], "welcome");
        assert_eq!(v["v"], 1);
        assert_eq!(v["phone_resize"], false);
        assert_eq!(v["limits"]["max_binary_frame"], MAX_BINARY_FRAME);

        let snap = ServerMsg::Snapshot {
            stream: 1,
            pane: PaneId("p".into()),
            cols: 80,
            rows: 24,
            alt_screen: false,
            offset: 10,
            lagged: false,
        };
        assert_eq!(
            serde_json::to_value(&snap).unwrap(),
            json!({"t":"snapshot","stream":1,"pane":"p","cols":80,"rows":24,"alt_screen":false,"offset":10,"lagged":false})
        );
        assert_eq!(
            serde_json::to_value(ServerMsg::TreeChanged {}).unwrap(),
            json!({"t":"tree_changed"})
        );
        assert_eq!(
            serde_json::to_value(ServerMsg::Pong { n: 4 }).unwrap(),
            json!({"t":"pong","n":4})
        );
        assert_eq!(
            serde_json::to_value(ServerMsg::SessionKilled {
                reason: "revoked".into()
            })
            .unwrap(),
            json!({"t":"session_killed","reason":"revoked"})
        );
        assert_eq!(
            serde_json::to_value(ServerMsg::error("unknown_type", "x")).unwrap(),
            json!({"t":"error","code":"unknown_type","message":"x"})
        );
        assert_eq!(
            serde_json::to_value(ServerMsg::action_ok(3, json!({}))).unwrap(),
            json!({"t":"result","id":3,"ok":true,"data":{}})
        );
        assert_eq!(
            serde_json::to_value(ServerMsg::action_err(3, "denied", "no")).unwrap(),
            json!({"t":"result","id":3,"ok":false,"error":{"code":"denied","message":"no"}})
        );
        assert_eq!(
            serde_json::to_value(ServerMsg::PaneState {
                pane: PaneId("p".into()),
                alt_screen: true,
                command_running: false,
                cwd: Some("/tmp".into()),
                title: None
            })
            .unwrap(),
            json!({"t":"pane_state","pane":"p","alt_screen":true,"command_running":false,"cwd":"/tmp","title":null})
        );
    }

    #[test]
    fn tree_shape_and_round_trip() {
        let tree = TreeSnapshot {
            windows: vec![WindowNode {
                id: "w1".into(),
                title: "win".into(),
                tabs: vec![TabNode {
                    id: "t1".into(),
                    title: "tab".into(),
                    active: true,
                    panes: vec![PaneNode {
                        id: PaneId("p1".into()),
                        session: "s1".into(),
                        title: "zsh".into(),
                        cwd: Some("/home".into()),
                        cols: 80,
                        rows: 24,
                        alt_screen: false,
                        focused: true,
                    }],
                }],
            }],
        };
        let msg = ServerMsg::Tree(tree.clone());
        let v = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["t"], "tree");
        assert_eq!(v["windows"][0]["tabs"][0]["panes"][0]["id"], "p1");
        let back: ServerMsg = serde_json::from_value(v).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn server_msg_ignores_unknown_fields() {
        let m: ServerMsg = serde_json::from_str(r#"{"t":"pong","n":1,"extra":true}"#).unwrap();
        assert_eq!(m, ServerMsg::Pong { n: 1 });
    }

    #[test]
    fn pair_bodies() {
        let req: PairRequestBody = serde_json::from_str(
            r#"{"v":1,"secret":"s3cret","device_name":"Pixel 8","platform":"android"}"#,
        )
        .unwrap();
        assert_eq!(req.secret.expose(), "s3cret");
        assert!(!format!("{req:?}").contains("s3cret"));
        assert_eq!(
            serde_json::to_value(PairResponse::Pending { poll: "abc".into() }).unwrap(),
            json!({"status":"pending","poll":"abc"})
        );
        assert_eq!(
            serde_json::to_value(PairResponse::Approved {
                device_id: "d".into(),
                token: SecretString::new("tok")
            })
            .unwrap(),
            json!({"status":"approved","device_id":"d","token":"tok"})
        );
        assert_eq!(
            serde_json::to_value(PairResponse::Denied).unwrap(),
            json!({"status":"denied"})
        );
        assert_eq!(
            serde_json::to_value(PairResponse::Expired).unwrap(),
            json!({"status":"expired"})
        );
        assert_eq!(
            serde_json::to_value(InfoResponse {
                protocol: 1,
                instance: "i".into(),
                name: "pc".into(),
                pairing: true
            })
            .unwrap(),
            json!({"protocol":1,"instance":"i","name":"pc","pairing":true})
        );
    }

    #[test]
    fn version_check() {
        assert!(check_version(1).is_ok());
        for bad in [0, 2, 99] {
            let ServerMsg::Error { code, .. } = check_version(bad).unwrap_err() else {
                panic!()
            };
            assert_eq!(code, "unsupported_version");
        }
    }

    #[test]
    fn binary_frames_round_trip() {
        let f = encode_output_frame(7, 0x0102_0304_0506_0708, b"hello").unwrap();
        assert_eq!(&f[..5], &[1, 0, 0, 0, 7]);
        assert_eq!(&f[5..13], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            decode_binary_frame(&f).unwrap(),
            BinaryFrame::Output {
                stream: 7,
                offset: 0x0102_0304_0506_0708,
                payload: b"hello"
            }
        );
        let f = encode_input_frame(2, b"\x1b[A").unwrap();
        assert_eq!(f, vec![2, 0, 0, 0, 2, 0x1b, b'[', b'A']);
        assert_eq!(
            decode_binary_frame(&f).unwrap(),
            BinaryFrame::Input {
                stream: 2,
                payload: b"\x1b[A"
            }
        );
        // Empty payloads are valid.
        assert!(decode_binary_frame(&encode_input_frame(1, b"").unwrap()).is_ok());
    }

    #[test]
    fn binary_frame_errors() {
        assert_eq!(decode_binary_frame(&[]), Err(FrameError::Short));
        assert_eq!(decode_binary_frame(&[1, 0, 0]), Err(FrameError::Short));
        assert_eq!(
            decode_binary_frame(&[1, 0, 0, 0, 1, 0, 0]),
            Err(FrameError::Short)
        );
        assert_eq!(decode_binary_frame(&[2, 0, 0]), Err(FrameError::Short));
        assert_eq!(
            decode_binary_frame(&[9, 0, 0, 0, 1]),
            Err(FrameError::UnknownKind(9))
        );
        let huge = vec![2u8; MAX_BINARY_FRAME + 1];
        assert_eq!(decode_binary_frame(&huge), Err(FrameError::TooLarge));
        let big_input = encode_input_frame(1, &vec![0; MAX_INPUT_PAYLOAD + 1]);
        assert_eq!(big_input, Err(FrameError::TooLarge));
        let mut raw = vec![2u8, 0, 0, 0, 1];
        raw.extend(vec![0; MAX_INPUT_PAYLOAD + 1]);
        assert_eq!(decode_binary_frame(&raw), Err(FrameError::TooLarge));
        assert_eq!(
            encode_output_frame(1, 0, &vec![0; MAX_OUTPUT_PAYLOAD + 1]),
            Err(FrameError::TooLarge)
        );
        assert!(encode_output_frame(1, 0, &vec![0; MAX_OUTPUT_PAYLOAD]).is_ok());
    }

    #[test]
    fn chunking() {
        let data = vec![7u8; MAX_OUTPUT_PAYLOAD * 2 + 5];
        let chunks: Vec<_> = chunk_output(100, &data).collect();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].0, 100);
        assert_eq!(chunks[1].0, 100 + MAX_OUTPUT_PAYLOAD as u64);
        assert_eq!(chunks[2].1.len(), 5);
        for (off, c) in chunks {
            assert!(encode_output_frame(1, off, c).unwrap().len() <= MAX_BINARY_FRAME);
        }
        assert_eq!(chunk_output(0, &[]).count(), 0);
    }
}
