/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use serde::Deserialize;
use serde::Serialize;

/// Represents a bidirectional stream of messages.
pub trait Channel<Req, Res>
where
    Req: Serialize,
    Res: for<'a> Deserialize<'a>,
{
    /// Sends a request, but does not expect a response. This is useful when
    /// some requests don't have an associated response.
    fn send(&self, item: &Req);

    /// Sends a request and waits for a response from the server.
    fn call(&self, item: &Req) -> Res;
}

pub type BoxChannel<Req, Res> = Box<dyn Channel<Req, Res> + Send + Sync + 'static>;

pub trait MakeClient {
    type Request: Serialize;
    type Response: for<'a> Deserialize<'a>;

    fn make_client(channel: BoxChannel<Self::Request, Self::Response>) -> Self;
}

// Dummy impl for (), so we can easily use this for tools that don't use global
// state.
impl MakeClient for () {
    type Request = ();
    type Response = ();

    fn make_client(_channel: BoxChannel<Self::Request, Self::Response>) -> Self {}
}

impl<T, Req, Res> Channel<Req, Res> for Box<T>
where
    T: Channel<Req, Res> + ?Sized,
    Req: Serialize,
    Res: for<'a> Deserialize<'a>,
{
    fn send(&self, item: &Req) {
        self.as_ref().send(item)
    }

    fn call(&self, item: &Req) -> Res {
        self.as_ref().call(item)
    }
}
