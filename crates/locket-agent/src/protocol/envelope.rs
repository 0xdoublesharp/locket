//! Request and response envelope types exchanged over the v1 protocol.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroize as _;

use crate::PROTOCOL_VERSION;
use crate::error::ProtocolError;
use crate::method::AgentMethod;

/// JSON request envelope sent after the v1 length prefix.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestEnvelope {
    /// Protocol version.
    pub v: u16,
    /// Client-generated request id.
    pub id: String,
    /// Method name.
    pub kind: String,
    /// Method payload.
    pub payload: Value,
}

impl std::fmt::Debug for RequestEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestEnvelope")
            .field("v", &self.v)
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("payload", &"[redacted]")
            .finish()
    }
}

impl Drop for RequestEnvelope {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.payload);
    }
}

fn zeroize_json_value(root: &mut Value) {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        match value {
            Value::String(secret) => secret.zeroize(),
            Value::Array(items) => stack.extend(items.iter_mut()),
            Value::Object(map) => stack.extend(map.values_mut()),
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
}

impl RequestEnvelope {
    /// Creates a v1 request envelope for a typed method.
    #[must_use]
    pub fn new(id: impl Into<String>, method: AgentMethod, payload: Value) -> Self {
        Self { v: PROTOCOL_VERSION, id: id.into(), kind: method.as_str().to_owned(), payload }
    }

    /// Returns the validated typed method.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnknownMethod`] when `kind` is not a supported
    /// v1 method name.
    pub fn method(&self) -> Result<AgentMethod, ProtocolError> {
        self.kind.parse().map_err(ProtocolError::UnknownMethod)
    }
}

/// JSON response envelope sent after the v1 length prefix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ResponseEnvelope {
    /// Successful response.
    Success(SuccessEnvelope),
    /// Error response.
    Error(ErrorEnvelope),
}

/// Successful response envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SuccessEnvelope {
    /// Protocol version.
    pub v: u16,
    /// Request id being answered.
    pub id: String,
    /// Success marker.
    pub ok: bool,
    /// Response payload.
    pub payload: Value,
}

impl SuccessEnvelope {
    /// Creates a successful v1 response.
    #[must_use]
    pub fn new(id: impl Into<String>, payload: Value) -> Self {
        Self { v: PROTOCOL_VERSION, id: id.into(), ok: true, payload }
    }

    /// Borrows the payload value.
    #[must_use]
    pub const fn payload(&self) -> &Value {
        &self.payload
    }
}

/// Error response envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErrorEnvelope {
    /// Protocol version.
    pub v: u16,
    /// Request id being answered.
    pub id: String,
    /// Success marker. Always false for this variant.
    pub ok: bool,
    /// Typed Locket error name.
    pub error: String,
    /// Redacted safe message.
    pub message: String,
    /// Whether the client may retry the request unchanged.
    pub retryable: bool,
}

impl ErrorEnvelope {
    /// Creates a redacted v1 error response.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        error: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: id.into(),
            ok: false,
            error: error.into(),
            message: message.into(),
            retryable,
        }
    }
}
