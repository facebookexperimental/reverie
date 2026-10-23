//! Linux LP64 socket syscall buffers, distinct from host libc wrappers.
//!
//! GNU's public aliases are retained. Musl's libc msghdr/cmsghdr use narrower
//! count fields and must not decode a raw guest sendmsg/recvmsg syscall buffer.
//! These structs are input/read adapters, not padding-preserving serializers.

use core::ffi::c_void;

/// Raw guest msghdr; GNU retains its existing public libc type.
#[cfg(not(target_env = "musl"))]
pub type Msghdr = libc::msghdr;

/// Linux LP64 guest message header, independent of musl's wrapper ABI.
#[cfg(target_env = "musl")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Msghdr {
    /// Optional socket name buffer in guest memory.
    pub msg_name: *mut c_void,
    /// Kernel socklen_t occupies 32 bits.
    pub msg_namelen: libc::socklen_t,
    name_padding: u32,
    /// Guest iovec array; only dereference through MemoryAccess.
    pub msg_iov: *mut libc::iovec,
    /// Full kernel size_t width, including values above u32::MAX.
    pub msg_iovlen: usize,
    /// Guest ancillary byte buffer.
    pub msg_control: *mut c_void,
    /// Full kernel size_t width.
    pub msg_controllen: usize,
    /// Message flag bit pattern.
    pub msg_flags: libc::c_int,
    flags_padding: u32,
}

/// Raw guest cmsghdr; GNU retains its existing public libc type.
#[cfg(not(target_env = "musl"))]
pub type Cmsghdr = libc::cmsghdr;

/// Linux LP64 ancillary header; every byte is an explicit integer field.
#[cfg(target_env = "musl")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Cmsghdr {
    /// Total control-message length, including this header.
    pub cmsg_len: usize,
    /// Ancillary protocol level.
    pub cmsg_level: libc::c_int,
    /// Ancillary message type.
    pub cmsg_type: libc::c_int,
}

/// Raw guest mmsghdr; GNU retains its existing public libc type.
#[cfg(not(target_env = "musl"))]
pub type Mmsghdr = libc::mmsghdr;

/// Linux LP64 message-batch entry with the kernel's 64-byte stride.
#[cfg(target_env = "musl")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Mmsghdr {
    /// Guest message header.
    pub msg_hdr: Msghdr,
    /// Per-message byte count returned by Linux.
    pub msg_len: libc::c_uint,
    length_padding: u32,
}

// Generated UAPI is the independent layout authority. Its net::iovec is opaque;
// use general::iovec to check the complete pointed-to record. Signedness of
// msg_flags/msg_namelen intentionally follows the existing GNU public API while
// retaining the identical 32-bit kernel bit representation.
const _: () = {
    use core::mem::align_of;
    use core::mem::offset_of;
    use core::mem::size_of;

    use linux_raw_sys::net::cmsghdr as C;
    use linux_raw_sys::net::mmsghdr as B;
    use linux_raw_sys::net::msghdr as M;
    assert!(size_of::<usize>() == 8);
    assert!(size_of::<libc::socklen_t>() == 4);
    assert!(size_of::<Msghdr>() == 56 && size_of::<Msghdr>() == size_of::<M>());
    assert!(align_of::<Msghdr>() == 8 && align_of::<Msghdr>() == align_of::<M>());
    assert!(size_of::<Cmsghdr>() == 16 && size_of::<Cmsghdr>() == size_of::<C>());
    assert!(align_of::<Cmsghdr>() == 8 && align_of::<Cmsghdr>() == align_of::<C>());
    assert!(size_of::<Mmsghdr>() == 64 && size_of::<Mmsghdr>() == size_of::<B>());
    assert!(align_of::<Mmsghdr>() == 8 && align_of::<Mmsghdr>() == align_of::<B>());
    macro_rules! same {
        ($ours:ty, $kernel:ty, $field:ident, $offset:expr) => {
            assert!(offset_of!($ours, $field) == $offset);
            assert!(offset_of!($ours, $field) == offset_of!($kernel, $field));
        };
    }
    same!(Msghdr, M, msg_name, 0);
    same!(Msghdr, M, msg_namelen, 8);
    same!(Msghdr, M, msg_iov, 16);
    same!(Msghdr, M, msg_iovlen, 24);
    same!(Msghdr, M, msg_control, 32);
    same!(Msghdr, M, msg_controllen, 40);
    same!(Msghdr, M, msg_flags, 48);
    same!(Cmsghdr, C, cmsg_len, 0);
    same!(Cmsghdr, C, cmsg_level, 8);
    same!(Cmsghdr, C, cmsg_type, 12);
    same!(Mmsghdr, B, msg_hdr, 0);
    same!(Mmsghdr, B, msg_len, 56);
    assert!(size_of::<libc::iovec>() == size_of::<linux_raw_sys::general::iovec>());
    assert!(align_of::<libc::iovec>() == align_of::<linux_raw_sys::general::iovec>());
    same!(libc::iovec, linux_raw_sys::general::iovec, iov_base, 0);
    same!(libc::iovec, linux_raw_sys::general::iovec, iov_len, 8);
    // SAFETY: all named fields are raw pointers/integers, zero is valid.
    // This checks field types only; no implicit padding is read as bytes.
    let message: Msghdr = unsafe { core::mem::zeroed() };
    let _: *mut c_void = message.msg_name;
    let _: libc::socklen_t = message.msg_namelen;
    let _: *mut libc::iovec = message.msg_iov;
    let _: usize = message.msg_iovlen;
    let _: *mut c_void = message.msg_control;
    let _: usize = message.msg_controllen;
    let _: libc::c_int = message.msg_flags;
    let control: Cmsghdr = unsafe { core::mem::zeroed() };
    let _: usize = control.cmsg_len;
    let _: libc::c_int = control.cmsg_level;
    let _: libc::c_int = control.cmsg_type;
    let batch: Mmsghdr = unsafe { core::mem::zeroed() };
    let _: Msghdr = batch.msg_hdr;
    let _: libc::c_uint = batch.msg_len;
};

#[cfg(target_env = "musl")]
const _: () = {
    assert!(core::mem::offset_of!(Msghdr, name_padding) == 12);
    assert!(core::mem::offset_of!(Msghdr, flags_padding) == 52);
    assert!(core::mem::offset_of!(Mmsghdr, length_padding) == 60);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Addr;
    use crate::AddrMut;
    use crate::LocalMemory;
    use crate::MemoryAccess;

    // Build initialized guest bytes, never reinterpret a returned padded
    // struct as a byte image. Deliberately dirty ABI padding tests field reads.
    fn message_bytes(fill: u8, iovlen: usize, controllen: usize) -> [u8; 56] {
        let mut bytes = [fill; 56];
        bytes[0..8].copy_from_slice(&0x1234usize.to_ne_bytes());
        bytes[8..12].copy_from_slice(&u32::MAX.to_ne_bytes());
        bytes[16..24].copy_from_slice(&0x2348usize.to_ne_bytes());
        bytes[24..32].copy_from_slice(&iovlen.to_ne_bytes());
        bytes[32..40].copy_from_slice(&0x3456usize.to_ne_bytes());
        bytes[40..48].copy_from_slice(&controllen.to_ne_bytes());
        bytes[48..52].copy_from_slice(&i32::MIN.to_ne_bytes());
        bytes
    }

    #[test]
    fn socket_message_reads_full_width_counts_and_ignores_padding() {
        for length in [0, u32::MAX as usize + 1, usize::MAX] {
            for fill in [0x55, 0xaa] {
                let mut guarded = [fill; 88];
                guarded[16..72].copy_from_slice(&message_bytes(fill, length, length));
                let before = guarded;
                let address = Addr::from_ptr(guarded[16..].as_ptr().cast::<Msghdr>()).unwrap();
                let call = crate::Sendmsg::new().with_msg(Some(address));
                let message: Msghdr = LocalMemory::new().read_value(call.msg().unwrap()).unwrap();
                assert_eq!(message.msg_name as usize, 0x1234);
                assert_eq!(message.msg_namelen, u32::MAX);
                assert_eq!(message.msg_iov as usize, 0x2348);
                assert_eq!(message.msg_iovlen, length);
                assert_eq!(message.msg_control as usize, 0x3456);
                assert_eq!(message.msg_controllen, length);
                assert_eq!(message.msg_flags, i32::MIN);
                let call = crate::Recvmsg::new()
                    .with_msg(AddrMut::from_ptr(guarded[16..].as_ptr().cast::<Msghdr>()));
                let received: Msghdr = LocalMemory::new().read_value(call.msg().unwrap()).unwrap();
                assert_eq!(received.msg_iovlen, length);
                assert_eq!(received.msg_controllen, length);
                assert_eq!(guarded, before);
            }
        }
    }

    #[test]
    fn socket_batch_uses_kernel_stride_and_preserves_each_count() {
        let mut guarded = [0x5au8; 160];
        for (index, length) in [u32::MAX as usize + 1, usize::MAX].into_iter().enumerate() {
            let offset = 16 + index * 64;
            guarded[offset..offset + 56].copy_from_slice(&message_bytes(0xaa, length, length));
            guarded[offset + 56..offset + 60].copy_from_slice(&(index as u32 + 3).to_ne_bytes());
        }
        let before = guarded;
        let address = AddrMut::from_ptr(guarded[16..].as_ptr().cast::<Mmsghdr>()).unwrap();
        let call = crate::Recvmmsg::new().with_mmsg(Some(address)).with_vlen(2);
        // SAFETY: raw pointers/integers admit zero; read_values initializes all
        // guest bytes. No object padding is exposed after the typed reads.
        let mut messages: [Mmsghdr; 2] = unsafe { core::mem::zeroed() };
        LocalMemory::new()
            .read_values(call.mmsg().unwrap().into(), &mut messages)
            .unwrap();
        assert_eq!(messages[0].msg_hdr.msg_iovlen, u32::MAX as usize + 1);
        assert_eq!(messages[1].msg_hdr.msg_iovlen, usize::MAX);
        assert_eq!(messages[0].msg_hdr.msg_controllen, u32::MAX as usize + 1);
        assert_eq!(messages[1].msg_hdr.msg_controllen, usize::MAX);
        assert_eq!(messages[0].msg_len, 3);
        assert_eq!(messages[1].msg_len, 4);
        let sent = crate::Sendmmsg::new().with_msgvec(Some(Addr::from(address).cast::<Msghdr>()));
        assert_eq!(sent.msgvec().unwrap().as_raw(), address.as_raw());
        assert_eq!(guarded, before);
    }

    #[test]
    fn socket_control_header_keeps_full_length_and_signed_fields() {
        for length in [16, u32::MAX as usize + 1, usize::MAX] {
            let mut guarded = [0x5au8; 48];
            guarded[16..24].copy_from_slice(&length.to_ne_bytes());
            guarded[24..28].copy_from_slice(&i32::MIN.to_ne_bytes());
            guarded[28..32].copy_from_slice(&(-1i32).to_ne_bytes());
            let before = guarded;
            let header: Cmsghdr = LocalMemory::new()
                .read_value(Addr::from_ptr(guarded[16..].as_ptr().cast::<Cmsghdr>()).unwrap())
                .unwrap();
            assert_eq!(header.cmsg_len, length);
            assert_eq!(header.cmsg_level, i32::MIN);
            assert_eq!(header.cmsg_type, -1);
            assert_eq!(guarded, before);
        }
    }
}
