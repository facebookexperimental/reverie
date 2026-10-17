//! LiteInst's use of the in-guest fallback continuation, which lives in
//! [`reverie_inguest::guest::continuation`]: it registers the runtime's
//! dispatch functions as the continuation's handlers and keeps the two
//! observation symbols the fixtures look up by name.

use std::io;
use std::sync::OnceLock;

use reverie_inguest::guest::context::RegisterContext;
use reverie_inguest::guest::continuation;
pub(crate) use reverie_inguest::guest::continuation::rebind_fork_child;
use reverie_inguest::guest::event::InstructionEventKind;

/// LiteInst's one registration of the continuation handlers, kept so that a
/// retried installation reuses it while a registration by another backend is
/// still refused.
static REGISTRATION: OnceLock<Result<(), io::ErrorKind>> = OnceLock::new();

/// Registers LiteInst's dispatch functions as the continuation's handlers
/// (once per process) and prepares this thread's continuation.
pub(crate) fn initialize() -> io::Result<()> {
    let region = reverie_inguest::guest::tool_region::ToolRegion::reserve()?;
    // SAFETY: this one cache always denotes these same dispatch functions.
    // They synchronously use the continuation's genuine saved register block
    // and interrupted PKRU, preserving the shared entry's safety contract.
    unsafe {
        continuation::initialize_registered(
            &REGISTRATION,
            continuation::ContinuationHandlers {
                syscall: dispatch_syscall,
                instruction: dispatch_instruction,
            },
            reverie_inguest::guest::tool_region::StackBacking::ToolRegion(region),
        )
    }
}

unsafe fn dispatch_syscall(context: *mut RegisterContext, pkru: &mut Option<u32>) {
    unsafe { crate::runtime::dispatch_fallback_context(context, pkru) };
}

unsafe fn dispatch_instruction(context: *mut RegisterContext, kind: InstructionEventKind) {
    unsafe { reverie_inguest::guest::installed_tool::dispatch_saved_instruction(context, kind) };
}

/// Diagnostic observations for the current thread's owned continuation.
/// Selectors 0/1/2 are actual fallback entry, reached ordinary callback, and
/// prepared genuine completion frame. They are not a kernel-stop census.
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_owned_fallback_observation(selector: u32) -> u64 {
    continuation::owned_observation(selector)
}

/// Check a fixture's actual callback local address against owned stack bounds.
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_on_owned_fallback_stack(address: usize) -> bool {
    continuation::on_owned_stack(address)
}
