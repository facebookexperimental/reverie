//! Standalone preload ownership. The shared core stays allocator neutral.
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(target_env = "gnu")]
mod glibc_compat;

#[cfg(not(test))]
mod constructor;

#[cfg(not(test))]
reverie_liteinst::declare_fixed_tool_allocator!();

#[cfg(test)]
reverie_liteinst::declare_legacy_private_tool_allocator!();

#[cfg(test)]
#[used]
#[unsafe(link_section = ".init_array")]
static REVERIE_LITEINST_INIT: unsafe extern "C" fn() =
    reverie_liteinst::reverie_liteinst_initialize;

// Libtest retains its original generic startup and resolver order. The real
// preload has one native root, which invokes the resolver after activation.
#[cfg(all(test, target_env = "gnu"))]
#[used]
#[unsafe(link_section = ".init_array")]
static RESOLVE_REAL_DL_FIND_OBJECT: extern "C" fn() = glibc_compat::resolve_real_dl_find_object;
