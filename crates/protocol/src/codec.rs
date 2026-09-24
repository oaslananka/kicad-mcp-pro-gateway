//! Newline-delimited JSON framing shared by the daemon's IPC server and its
//! CLI/desktop clients.
//!
//! [`read_message`] enforces [`MAX_MESSAGE_BYTES`] while reading — a
//! misbehaving or malicious peer that never sends a newline cannot cause
//! unbounded allocation; it hits [`CodecError::MessageTooLarge`] instead.

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Local IPC is a trusted-local, low-volume control channel, not a bulk
/// data path — 1 MiB is generous headroom for any status/session/workspace
/// payload while still bounding worst-case memory use per message.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed json message: {0}")]
    Json(#[from] serde_json::Error),
    #[error("connection closed before a full message was received")]
    ConnectionClosed,
    #[error("message exceeds the maximum allowed size of {max} bytes")]
    MessageTooLarge { max: usize },
}

pub async fn write_message<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), CodecError> {
    let mut json = serde_json::to_vec(value)?;
    if json.len() > MAX_MESSAGE_BYTES {
        return Err(CodecError::MessageTooLarge {
            max: MAX_MESSAGE_BYTES,
        });
    }
    json.push(b'\n');
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_message<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T, CodecError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            if buf.is_empty() {
                return Err(CodecError::ConnectionClosed);
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > MAX_MESSAGE_BYTES {
            return Err(CodecError::MessageTooLarge {
                max: MAX_MESSAGE_BYTES,
            });
        }
    }

    Ok(serde_json::from_slice(&buf)?)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Sample {
        value: u32,
        label: String,
    }

    #[tokio::test]
    async fn write_then_read_round_trips() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let sample = Sample {
            value: 7,
            label: "hello".into(),
        };

        write_message(&mut client, &sample).await.unwrap();
        let received: Sample = read_message(&mut server).await.unwrap();

        assert_eq!(received, sample);
    }

    #[tokio::test]
    async fn reading_from_a_closed_connection_with_no_data_errors() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);

        let result: Result<Sample, _> = read_message(&mut server).await;
        assert!(matches!(result, Err(CodecError::ConnectionClosed)));
    }

    #[tokio::test]
    async fn oversized_message_without_newline_is_rejected_not_allocated_unbounded() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024 * 1024);
        let oversized = vec![b'a'; MAX_MESSAGE_BYTES + 10];
        client.write_all(&oversized).await.unwrap();
        drop(client);

        let result: Result<Sample, _> = read_message(&mut server).await;
        assert!(matches!(result, Err(CodecError::MessageTooLarge { .. })));
    }
}
