use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use super::CaptureOptions;
use super::ordered;

/// An inactive ordered capture mapping and its two owned lifetime endpoints.
///
/// Construction consumes exactly the host setup message. The guest setup
/// message remains pending. There are no producers, collector, threads,
/// callbacks, `Arc`s or locks in this value. Dropping it releases this process's
/// mapping and descriptor aliases without closing shared admission state.
///
/// This is preparation only: it cannot yield a capture report or establish
/// worker completion, guest reap, or stable publication. It is deliberately
/// not cloneable; duplicating an endpoint does not duplicate its setup message.
///
/// ```compile_fail
/// use reverie_rpc_transport::guest_log::InertCapturePlan;
/// fn cannot_duplicate(plan: InertCapturePlan) {
///     let _ = plan.clone();
/// }
/// ```
pub struct InertCapturePlan {
    options: CaptureOptions,
    buffer: ordered::Buffer,
    host: UnixStream,
    guest: UnixStream,
}

impl InertCapturePlan {
    /// Prepare shared storage without activating either role.
    ///
    /// # Safety
    /// Every mapping, descriptor alias and clone descendant must obey the
    /// [shared-memory contract](super::super), including immutable layout and
    /// exclusive producer/collector ownership. After clone, each branch must
    /// construct its own process-local wrappers and close its unused endpoint
    /// aliases. No active capture, lock, worker or reference-counted wrapper may
    /// be inherited and reused as part of this plan's later activation.
    /// These requirements do not establish a complete split capture lifecycle.
    ///
    /// ```compile_fail,E0133
    /// use reverie_rpc_transport::guest_log::{CaptureOptions, InertCapturePlan};
    /// fn requires_ownership_contract(options: CaptureOptions) {
    ///     let _ = InertCapturePlan::new(options);
    /// }
    /// ```
    pub unsafe fn new(options: CaptureOptions) -> io::Result<Self> {
        unsafe { Self::for_startup(options) }.map(|(plan, _deadline)| plan)
    }

    // Keep the old prepared_capture deadline before channel allocation/import.
    // An inert plan has no active startup deadline of its own.
    pub(super) unsafe fn for_startup(options: CaptureOptions) -> io::Result<(Self, Instant)> {
        if options.limits.diagnostic_bytes == 0
            || options.limits.diagnostic_bytes > 32 * 1024 * 1024
            || [
                options.timeouts.startup,
                options.timeouts.blocked_publication,
                options.timeouts.final_drain,
            ]
            .iter()
            .any(|duration| duration.is_zero() || Instant::now().checked_add(*duration).is_none())
        {
            return Err(io::Error::other("invalid capture bounds/deadlines"));
        }
        let deadline = Instant::now() + options.timeouts.startup;
        let (host, guest) = unsafe { ordered::channel_pair(options.limits.ordered()) }?;
        let buffer = unsafe { ordered::Buffer::receive_unshared(host.as_raw_fd()) }?;
        Ok((
            Self {
                options,
                buffer,
                host,
                guest,
            },
            deadline,
        ))
    }

    pub(super) fn options(&self) -> CaptureOptions {
        self.options
    }

    // Activation remains private to the local and split ownership facades.
    pub(super) fn into_local_parts(
        self,
    ) -> (CaptureOptions, ordered::Buffer, UnixStream, UnixStream) {
        (self.options, self.buffer, self.host, self.guest)
    }
}
