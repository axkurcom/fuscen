// Simple framing protocol inside encrypted payloads
use std::fmt;

/// Logical stream id
pub type StreamId = u16;

/// Control stream id
pub const STREAM_ID_CONTROL: StreamId = 0;

/// Default data stream id
pub const STREAM_ID_DATA_DEFAULT: StreamId = 1;

/// Outer frame type after decryption
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FrameType {
    // Data payload
    Data = 0x01,
    // Control payload
    Control = 0x02,
}

impl FrameType {
    /// Map byte to enum
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(FrameType::Data),
            0x02 => Some(FrameType::Control),
            _ => None,
        }
    }
}

/// Control message type ids
pub const CTRL_MSG_HELLO: u8 = 0x01;
pub const CTRL_MSG_STREAM_BIND: u8 = 0x02;
pub const CTRL_MSG_STREAM_CLOSE: u8 = 0x03;
pub const CTRL_MSG_REKEY: u8 = 0x04;
pub const CTRL_MSG_PING: u8 = 0x05;
pub const CTRL_MSG_PONG: u8 = 0x06;
pub const CTRL_MSG_ERROR: u8 = 0x07;

/// Protocol version in Hello
pub const PROTOCOL_VERSION: u8 = 1;

/// Control-plane messages
#[derive(Debug, Clone)]
pub enum ControlMessage {
    /// Client/server hello
    Hello { version: u8, flags: u8 },

    /// Reserved stream binding
    StreamBind { stream_id: StreamId },

    /// Logical stream close
    StreamClose { stream_id: StreamId },

    /// Rekey request placeholder
    RekeyRequest { new_epoch_id: u32 },

    /// Liveness ping
    Ping { opaque: Vec<u8> },

    /// Liveness pong
    Pong { opaque: Vec<u8> },

    /// Error report
    Error { code: u16, message: String },
}

/// Decoder errors
#[derive(Debug)]
pub enum ProtocolError {
    TooShort,
    UnknownFrameType(u8),
    UnknownControlType(u8),
    Malformed(&'static str),
    Utf8Error,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::TooShort => write!(f, "frame is too short"),
            ProtocolError::UnknownFrameType(t) => write!(f, "unknown frame type 0x{:02X}", t),
            ProtocolError::UnknownControlType(t) => {
                write!(f, "unknown control type 0x{:02X}", t)
            }
            ProtocolError::Malformed(s) => write!(f, "malformed control frame: {}", s),
            ProtocolError::Utf8Error => write!(f, "invalid UTF-8 in control message"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Encode frame header + payload
/// Layout [type:1][stream:2 BE][payload...]
pub fn encode_frame(frame_type: FrameType, stream_id: StreamId, payload: &[u8], out: &mut Vec<u8>) {
    // Reuse buffer
    out.clear();
    out.reserve(3 + payload.len());
    out.push(frame_type as u8);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
}

/// Decode frame header and return payload slice
pub fn decode_frame<'a>(buf: &'a [u8]) -> Result<(FrameType, StreamId, &'a [u8]), ProtocolError> {
    // Need at least 3 bytes
    if buf.len() < 3 {
        return Err(ProtocolError::TooShort);
    }

    let ft = FrameType::from_u8(buf[0]).ok_or(ProtocolError::UnknownFrameType(buf[0]))?;
    let sid = u16::from_be_bytes([buf[1], buf[2]]);
    let payload = &buf[3..];

    Ok((ft, sid, payload))
}

/// Encode control message into payload bytes
pub fn encode_control(msg: &ControlMessage, out: &mut Vec<u8>) {
    // Reuse buffer
    out.clear();
    match msg {
        ControlMessage::Hello { version, flags } => {
            out.push(CTRL_MSG_HELLO);
            out.push(*version);
            out.push(*flags);
        }
        ControlMessage::StreamBind { stream_id } => {
            out.push(CTRL_MSG_STREAM_BIND);
            out.extend_from_slice(&stream_id.to_be_bytes());
        }
        ControlMessage::StreamClose { stream_id } => {
            out.push(CTRL_MSG_STREAM_CLOSE);
            out.extend_from_slice(&stream_id.to_be_bytes());
        }
        ControlMessage::RekeyRequest { new_epoch_id } => {
            out.push(CTRL_MSG_REKEY);
            out.extend_from_slice(&new_epoch_id.to_be_bytes());
        }
        ControlMessage::Ping { opaque } => {
            out.push(CTRL_MSG_PING);
            out.extend_from_slice(&(opaque.len() as u32).to_be_bytes());
            out.extend_from_slice(opaque);
        }
        ControlMessage::Pong { opaque } => {
            out.push(CTRL_MSG_PONG);
            out.extend_from_slice(&(opaque.len() as u32).to_be_bytes());
            out.extend_from_slice(opaque);
        }
        ControlMessage::Error { code, message } => {
            out.push(CTRL_MSG_ERROR);
            out.extend_from_slice(&code.to_be_bytes());
            let b = message.as_bytes();
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(b);
        }
    }
}

/// Decode control message from payload bytes
pub fn decode_control(buf: &[u8]) -> Result<ControlMessage, ProtocolError> {
    // Need at least type byte
    if buf.is_empty() {
        return Err(ProtocolError::TooShort);
    }

    let kind = buf[0];
    let mut p = &buf[1..];

    // Small readers
    let mut read_u8 = |d: &mut &[u8]| -> Result<u8, ProtocolError> {
        if d.is_empty() {
            return Err(ProtocolError::TooShort);
        }
        let v = d[0];
        *d = &d[1..];
        Ok(v)
    };

    let mut read_u16 = |d: &mut &[u8]| -> Result<u16, ProtocolError> {
        if d.len() < 2 {
            return Err(ProtocolError::TooShort);
        }
        let mut tmp = [0u8; 2];
        tmp.copy_from_slice(&d[..2]);
        *d = &d[2..];
        Ok(u16::from_be_bytes(tmp))
    };

    let mut read_u32 = |d: &mut &[u8]| -> Result<u32, ProtocolError> {
        if d.len() < 4 {
            return Err(ProtocolError::TooShort);
        }
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&d[..4]);
        *d = &d[4..];
        Ok(u32::from_be_bytes(tmp))
    };

    let mut read_bytes = |d: &mut &[u8], len: usize| -> Result<Vec<u8>, ProtocolError> {
        if d.len() < len {
            return Err(ProtocolError::TooShort);
        }
        let v = d[..len].to_vec();
        *d = &d[len..];
        Ok(v)
    };

    match kind {
        CTRL_MSG_HELLO => {
            let version = read_u8(&mut p)?;
            let flags = read_u8(&mut p)?;
            Ok(ControlMessage::Hello { version, flags })
        }
        CTRL_MSG_STREAM_BIND => {
            let sid = read_u16(&mut p)?;
            Ok(ControlMessage::StreamBind { stream_id: sid })
        }
        CTRL_MSG_STREAM_CLOSE => {
            let sid = read_u16(&mut p)?;
            Ok(ControlMessage::StreamClose { stream_id: sid })
        }
        CTRL_MSG_REKEY => {
            let epoch = read_u32(&mut p)?;
            Ok(ControlMessage::RekeyRequest { new_epoch_id: epoch })
        }
        CTRL_MSG_PING => {
            let len = read_u32(&mut p)? as usize;
            let opaque = read_bytes(&mut p, len)?;
            Ok(ControlMessage::Ping { opaque })
        }
        CTRL_MSG_PONG => {
            let len = read_u32(&mut p)? as usize;
            let opaque = read_bytes(&mut p, len)?;
            Ok(ControlMessage::Pong { opaque })
        }
        CTRL_MSG_ERROR => {
            let code = read_u16(&mut p)?;
            let len = read_u32(&mut p)? as usize;
            let b = read_bytes(&mut p, len)?;
            let msg = String::from_utf8(b).map_err(|_| ProtocolError::Utf8Error)?;
            Ok(ControlMessage::Error { code, message: msg })
        }
        other => Err(ProtocolError::UnknownControlType(other)),
    }
}