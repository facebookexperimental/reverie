/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Reservations within one stopped task's bounded stack scratch window.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

use safeptrace::TraceeGeneration;

use super::REDZONE_SIZE;
use super::STACK_CAPACITY;

#[derive(Debug, Default)]
pub(crate) struct StackArena(Mutex<ArenaState>);

#[derive(Debug, Default)]
struct ArenaState {
    anchor: Option<Anchor>,
    next_id: u64,
    builder: Option<(u64, usize)>,
    // A committed frame cannot grow. Keeping its own ID makes out-of-order
    // drops safe; a released outer frame never releases an inner frame.
    frames: BTreeMap<u64, (usize, usize)>,
}

#[derive(Debug)]
struct Anchor {
    generation: TraceeGeneration,
    rsp: usize,
    top: usize,
    bottom: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum CheckoutError {
    Uncommitted,
    ChangedContext,
    AddressUnderflow,
    IdExhausted,
}

#[derive(Debug)]
pub(super) struct StackToken {
    arena: Arc<StackArena>,
    id: u64,
    top: usize,
    bottom: usize,
    committed: bool,
}

impl StackToken {
    pub(super) fn acquire(
        arena: Arc<StackArena>,
        generation: TraceeGeneration,
        rsp: usize,
    ) -> Result<Self, CheckoutError> {
        // No guest memory request or await occurs while this lock is held.
        let mut state = arena.0.lock().expect("guest stack arena mutex poisoned");
        if state.builder.is_some() {
            return Err(CheckoutError::Uncommitted);
        }
        let top = rsp
            .checked_sub(REDZONE_SIZE)
            .ok_or(CheckoutError::AddressUnderflow)?;
        let bottom = top
            .checked_sub(STACK_CAPACITY)
            .ok_or(CheckoutError::AddressUnderflow)?;
        if let Some(anchor) = &state.anchor
            && (anchor.generation != generation || anchor.rsp != rsp)
        {
            return Err(CheckoutError::ChangedContext);
        }
        let id = state.next_id;
        let next_id = id.checked_add(1).ok_or(CheckoutError::IdExhausted)?;
        let anchor = state.anchor.get_or_insert(Anchor {
            generation,
            rsp,
            top,
            bottom,
        });
        let arena_top = anchor.top;
        let bottom = anchor.bottom;
        // Do not reuse a hole above a live frame: allocation stays downward
        // and the aggregate bound remains the original scratch window.
        let top = state
            .frames
            .values()
            .map(|&(bottom, _)| bottom)
            .min()
            .unwrap_or(arena_top);
        state.next_id = next_id;
        state.builder = Some((id, top));
        drop(state);
        Ok(Self {
            arena,
            id,
            top,
            bottom,
            committed: false,
        })
    }

    #[cfg(test)]
    pub(super) fn arena(&self) -> Arc<StackArena> {
        self.arena.clone()
    }

    pub(super) fn top(&self) -> usize {
        self.top
    }

    pub(super) fn capacity(&self) -> usize {
        self.top - self.bottom
    }

    pub(super) fn commit(mut self, bottom: usize) -> Self {
        assert!(
            self.bottom <= bottom && bottom <= self.top,
            "committed guest stack frame escaped its reservation"
        );
        {
            let mut state = self
                .arena
                .0
                .lock()
                .expect("guest stack arena mutex poisoned");
            assert_eq!(state.builder, Some((self.id, self.top)));
            state.builder = None;
            assert!(state.frames.insert(self.id, (bottom, self.top)).is_none());
        }
        self.committed = true;
        self
    }
}

impl Drop for StackToken {
    fn drop(&mut self) {
        let mut state = self
            .arena
            .0
            .lock()
            .expect("guest stack arena mutex poisoned");
        if self.committed {
            assert!(state.frames.remove(&self.id).is_some());
        } else {
            assert_eq!(state.builder, Some((self.id, self.top)));
            state.builder = None;
        }
        if state.builder.is_none() && state.frames.is_empty() {
            state.anchor = None;
        }
    }
}

#[cfg(test)]
impl StackArena {
    pub(super) fn live(&self) -> usize {
        let state = self.0.lock().unwrap();
        state.frames.len() + usize::from(state.builder.is_some())
    }
}

#[cfg(test)]
mod tests {
    use reverie::Pid;
    use safeptrace::Stopped;

    use super::*;

    fn generation() -> TraceeGeneration {
        // Identity only: no ptrace operation is performed on this task.
        Stopped::new_unchecked(Pid::from_raw(std::process::id() as i32)).generation()
    }

    const RSP: usize = 0x10000;

    #[test]
    fn an_uncommitted_frame_excludes_another_builder_and_drop_allows_retry() {
        let arena = Arc::new(StackArena::default());
        let generation = generation();
        let outer = StackToken::acquire(arena.clone(), generation.clone(), RSP).unwrap();
        assert_eq!(arena.live(), 1);
        assert_eq!(
            StackToken::acquire(arena.clone(), generation.clone(), RSP).unwrap_err(),
            CheckoutError::Uncommitted
        );
        drop(outer);
        assert_eq!(arena.live(), 0);
        let retry = StackToken::acquire(arena.clone(), generation, RSP).unwrap();
        assert_eq!(retry.top(), RSP - REDZONE_SIZE);
        assert_eq!(retry.capacity(), STACK_CAPACITY);
    }

    #[test]
    fn committed_frames_are_disjoint_and_share_the_original_capacity() {
        let arena = Arc::new(StackArena::default());
        let generation = generation();
        let outer = StackToken::acquire(arena.clone(), generation.clone(), RSP).unwrap();
        let outer_top = outer.top();
        let outer = outer.commit(outer_top - 568);
        let inner = StackToken::acquire(arena.clone(), generation.clone(), RSP).unwrap();
        assert_eq!(inner.top(), outer_top - 568);
        assert_eq!(inner.capacity(), STACK_CAPACITY - 568);
        let inner_top = inner.top();
        let inner = inner.commit(inner_top - 128);
        let last = StackToken::acquire(arena.clone(), generation.clone(), RSP).unwrap();
        assert_eq!(last.top(), outer_top - 696);
        assert_eq!(last.capacity(), STACK_CAPACITY - 696);
        let last = last.commit(outer_top - STACK_CAPACITY);
        let exhausted = StackToken::acquire(arena.clone(), generation.clone(), RSP).unwrap();
        assert_eq!(exhausted.capacity(), 0);
        drop(exhausted);
        drop(last);
        drop(inner);
        drop(outer);
        assert_eq!(arena.live(), 0);
        let fresh = StackToken::acquire(arena, generation, RSP).unwrap();
        assert_eq!(fresh.capacity(), STACK_CAPACITY);
    }

    #[test]
    fn dropping_outer_and_middle_frames_does_not_release_the_innermost() {
        let arena = Arc::new(StackArena::default());
        let generation = generation();
        let outer = StackToken::acquire(arena.clone(), generation.clone(), RSP).unwrap();
        let top = outer.top();
        let outer = outer.commit(top - 64);
        let middle = StackToken::acquire(arena.clone(), generation.clone(), RSP)
            .unwrap()
            .commit(top - 128);
        let inner = StackToken::acquire(arena.clone(), generation.clone(), RSP)
            .unwrap()
            .commit(top - 192);
        drop(middle);
        drop(outer);
        let next = StackToken::acquire(arena.clone(), generation.clone(), RSP).unwrap();
        assert_eq!(next.top(), top - 192);
        assert_eq!(arena.live(), 2);
        drop(inner);
        assert_eq!(arena.live(), 1);
        // The live builder's bounded interval does not expand as others drop.
        assert_eq!(next.capacity(), STACK_CAPACITY - 192);
        drop(next);
        assert_eq!(arena.live(), 0);
        assert_eq!(
            StackToken::acquire(arena, generation, RSP).unwrap().top(),
            top
        );
    }

    #[test]
    fn a_live_arena_refuses_changed_context_but_empty_arena_can_reanchor() {
        let arena = Arc::new(StackArena::default());
        let generation = generation();
        let frame = StackToken::acquire(arena.clone(), generation.clone(), RSP).unwrap();
        let top = frame.top();
        let frame = frame.commit(top - 8);
        assert_eq!(
            StackToken::acquire(arena.clone(), generation.clone(), RSP + 8).unwrap_err(),
            CheckoutError::ChangedContext
        );
        let other = Stopped::new_unchecked(Pid::from_raw(unsafe { libc::getppid() })).generation();
        assert_ne!(generation, other);
        assert_eq!(
            StackToken::acquire(arena.clone(), other, RSP).unwrap_err(),
            CheckoutError::ChangedContext
        );
        assert_eq!(arena.live(), 1);
        drop(frame);
        let reanchored = StackToken::acquire(arena, generation, RSP + 8).unwrap();
        assert_eq!(reanchored.top(), RSP + 8 - REDZONE_SIZE);
    }

    #[test]
    fn an_invalid_checkout_cannot_poison_a_later_valid_acquisition() {
        let arena = Arc::new(StackArena::default());
        let generation = generation();
        assert_eq!(
            StackToken::acquire(arena.clone(), generation.clone(), 1).unwrap_err(),
            CheckoutError::AddressUnderflow
        );
        assert_eq!(arena.live(), 0);
        let valid = StackToken::acquire(arena.clone(), generation, RSP).unwrap();
        assert_eq!(valid.capacity(), STACK_CAPACITY);
        drop(valid);
        assert_eq!(arena.live(), 0);
    }

    #[test]
    fn old_image_guards_cannot_release_new_image_frames() {
        let generation = generation();
        let mut current = Arc::new(StackArena::default());
        let old_arena = current.clone();
        let old = StackToken::acquire(current.clone(), generation.clone(), RSP).unwrap();
        let old_top = old.top();
        let old = old.commit(old_top - 64);
        // This is the arena replacement at successful exec, before callbacks.
        current = Arc::new(StackArena::default());
        let new = StackToken::acquire(current.clone(), generation, RSP).unwrap();
        let new_top = new.top();
        let new = new.commit(new_top - 128);
        drop(old);
        assert_eq!(old_arena.live(), 0);
        assert_eq!(current.live(), 1);
        drop(new);
        assert_eq!(current.live(), 0);
    }
}
