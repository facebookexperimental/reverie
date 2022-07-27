/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use std::future::Future;
use std::mem;
use std::pin::Pin;
use std::slice;
use std::task::Context;
use std::task::Poll;

use futures::future::FutureExt;

/// Represents a set of children.
#[derive(Clone, Default)]
pub struct Children<T> {
    inner: Vec<T>,
}

impl<'a, T> IntoIterator for &'a Children<T> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> slice::Iter<'a, T> {
        self.inner.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Children<T> {
    type Item = &'a mut T;
    type IntoIter = slice::IterMut<'a, T>;

    fn into_iter(self) -> slice::IterMut<'a, T> {
        self.inner.iter_mut()
    }
}

#[allow(unused)]
impl<T> Children<T> {
    pub fn new() -> Self {
        Children { inner: Vec::new() }
    }

    pub fn push(&mut self, item: T) {
        self.inner.push(item);
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn into_inner(self) -> Vec<T> {
        self.inner
    }

    pub fn take_inner(&mut self) -> Vec<T> {
        mem::take(&mut self.inner)
    }

    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.inner.retain(f)
    }
}

impl<T> Future for Children<T>
where
    T: Future + Unpin,
{
    // (Orphans, Finished)
    type Output = (Self, Vec<T::Output>);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut inner = mem::take(&mut self.inner);
        let mut ready = Vec::new();

        // Iterate backwards through the vec. If an item is ready, swap_remove
        // it. It is important to iterate backwards so that swap_remove doesn't
        // perturb the ordering on the part of the vec we haven't yet iterated
        // over.
        for i in (0..self.inner.len()).rev() {
            if let Poll::Ready(x) = inner[i].poll_unpin(cx) {
                inner.swap_remove(i);
                ready.push(x);
            }
        }

        Poll::Ready((Children { inner }, ready))
    }
}
