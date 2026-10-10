//! Standalone preload ownership. The shared core stays allocator neutral.
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(target_env = "gnu")]
mod glibc_compat;

#[cfg(not(test))]
mod constructor;

#[global_allocator]
static ALLOCATOR: reverie_liteinst::PrivateToolAllocator = reverie_liteinst::PrivateToolAllocator;

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
