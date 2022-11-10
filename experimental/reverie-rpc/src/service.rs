/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Service {
    type Request<'r>: Deserialize<'r> + Unpin + Send
    where
        Self: 'r;
    type Response: Serialize + Send + Unpin;
    type Future<'a>: Future<Output = Option<Self::Response>> + Send + 'a
    where
        Self: 'a;

    /// Makes a "call" to our service. Returns `None` if the service has no
    /// response for the client (i.e., it was a send-only request).
    fn call<'a>(&'a self, req: Self::Request<'a>) -> Self::Future<'a>;
}

impl<S> Service for Arc<S>
where
    S: Service,
{
    type Request<'r> = S::Request<'r> where S: 'r;
    type Response = S::Response;
    type Future<'a>
    = S::Future<'a> where S: 'a;

    fn call<'a>(&'a self, req: Self::Request<'a>) -> Self::Future<'a> {
        self.as_ref().call(req)
    }
}

impl Service for () {
    type Request<'r> = ();
    type Response = ();
    type Future<'a> = core::future::Ready<Option<()>>;

    fn call<'a>(&'a self, _req: ()) -> Self::Future<'a> {
        core::future::ready(Some(()))
    }
}
