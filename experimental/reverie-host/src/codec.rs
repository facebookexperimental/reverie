/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::marker::Unpin;
use std::io;

use serde::Deserialize;
use serde::Serialize;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

pub async fn read<'a, T, S>(stream: &mut S, buf: &'a mut Vec<u8>) -> io::Result<T>
where
    T: Deserialize<'a>,
    S: AsyncRead + Unpin,
{
    let len = stream.read_u32().await? as usize;

    buf.resize(len, 0);

    stream.read_exact(buf).await?;

    reverie_rpc::decode_frame(buf)
}

pub async fn write<T, S>(stream: &mut S, buf: &mut Vec<u8>, item: T) -> io::Result<()>
where
    T: Serialize,
    S: AsyncWrite + Unpin,
{
    buf.clear();

    reverie_rpc::encode(&item, buf)?;

    stream.write_all(buf).await
}
