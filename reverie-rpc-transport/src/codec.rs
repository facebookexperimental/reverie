/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Length-prefixed bincode framing over any async byte stream.
//!
//! Wire format of a single frame:
//!
//! ```text
//! +-----------------------+-------------------------------+
//! | u32 length (big-end)  |  bincode-serialized payload   |
//! +-----------------------+-------------------------------+
//! ```
//!
//! (De)serialization is split from I/O on purpose: [`encode`]/[`decode`] are
//! synchronous and produce/consume owned `Vec<u8>`, while [`write_message`] and
//! [`read_message`] move only owned bytes across `await` points. This matters
//! because [`reverie::GlobalTool::Request`]/`Response` are bounded `Send` but
//! **not** `Sync`, so a borrow `&Request` held across an await would make the
//! surrounding future non-`Send` and break `tokio::spawn` / the `async_trait`
//! `Send` future bound. Serializing first, then writing bytes, keeps every
//! future `Send`.
//!
//! The same [`bincode`] configuration must be used on both ends. We use
//! [`bincode::config::legacy`] to match the configuration already used
//! elsewhere in the Reverie tree (for example `reverie-ptrace`'s debug-mode RPC
//! round-trip and the gdbstub register codec), so payloads are byte compatible
//! across those call sites.

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

use crate::error::RpcError;

/// Default maximum accepted frame size (16 MiB). GlobalTool RPC messages are
/// tiny (tens to a few hundred bytes), so this is a generous guard against a
/// corrupt length prefix rather than a real workload limit.
pub const DEFAULT_MAX_FRAME_LEN: usize = 16 * (1 << 20);

/// Serialize `value` to bincode bytes.
///
/// Synchronous and borrow-scoped: the `&T` borrow does not escape this call, so
/// callers never hold it across an `await`.
pub fn encode<T>(value: &T) -> Result<Vec<u8>, RpcError>
where
    T: Serialize + ?Sized,
{
    Ok(bincode::serde::encode_to_vec(
        value,
        bincode::config::legacy(),
    )?)
}

/// Deserialize a `T` from bincode bytes.
pub fn decode<T>(bytes: &[u8]) -> Result<T, RpcError>
where
    T: DeserializeOwned,
{
    let (value, _consumed) = bincode::serde::decode_from_slice(bytes, bincode::config::legacy())?;
    Ok(value)
}

/// Write `payload` as one length-prefixed frame and flush.
pub async fn write_message<W>(writer: &mut W, payload: &[u8]) -> Result<(), RpcError>
where
    W: AsyncWrite + Unpin,
{
    let len = u32::try_from(payload.len()).map_err(|_| RpcError::FrameTooLarge {
        len: payload.len(),
        max: u32::MAX as usize,
    })?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame, returning its raw payload bytes.
///
/// Returns [`RpcError::Closed`] if the peer closes the connection exactly at a
/// frame boundary (a clean disconnect), and propagates a mid-frame EOF as an
/// I/O error.
pub async fn read_message<R>(reader: &mut R, max_len: usize) -> Result<Vec<u8>, RpcError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        // A clean EOF *before any byte of the header* is a graceful close.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(RpcError::Closed);
        }
        Err(e) => return Err(RpcError::Io(e)),
    }

    let len = u32::from_be_bytes(header) as usize;
    if len > max_len {
        return Err(RpcError::FrameTooLarge { len, max: max_len });
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Convenience: serialize `value` and write it as one frame.
///
/// Serialization happens before any `await`, so the `&T` borrow is not held
/// across the write and the returned future is `Send` whenever `T: Send`.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), RpcError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let payload = encode(value)?;
    write_message(writer, &payload).await
}

/// Convenience: read one frame and deserialize it as `T`, using
/// [`DEFAULT_MAX_FRAME_LEN`].
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, RpcError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let bytes = read_message(reader, DEFAULT_MAX_FRAME_LEN).await?;
    decode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_in_memory() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);

        let sent: Vec<(u64, String)> = vec![(1, "one".into()), (2, "two".into())];
        let sent_clone = sent.clone();

        let writer = tokio::spawn(async move {
            write_frame(&mut a, &sent_clone).await.unwrap();
        });

        let got: Vec<(u64, String)> = read_frame(&mut b).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, sent);
    }

    #[test]
    fn encode_decode_are_inverse() {
        let value = (7u64, "seven".to_string(), vec![1u8, 2, 3]);
        let bytes = encode(&value).unwrap();
        let back: (u64, String, Vec<u8>) = decode(&bytes).unwrap();
        assert_eq!(value, back);
    }

    #[tokio::test]
    async fn clean_close_reports_closed() {
        let (a, mut b) = tokio::io::duplex(1024);
        drop(a); // close the write end with nothing sent
        let err = read_frame::<_, u64>(&mut b).await.unwrap_err();
        assert!(matches!(err, RpcError::Closed), "got {err:?}");
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        // Hand-craft a header claiming a huge payload.
        let bogus_len: u32 = 1_000_000;
        a.write_all(&bogus_len.to_be_bytes()).await.unwrap();
        a.flush().await.unwrap();
        let err = read_message(&mut b, 1024).await.unwrap_err();
        assert!(
            matches!(err, RpcError::FrameTooLarge { len, max } if len == 1_000_000 && max == 1024),
            "got {err:?}"
        );
    }
}
