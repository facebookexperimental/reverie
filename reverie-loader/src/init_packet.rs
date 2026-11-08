/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! HLISUC01 successor-init packet. On the exec-stop successor
//! route it occupies HLSCAL01 table 3; a first-image blob's
//! table 3 carries the tool-defined ordinary initialization
//! packet instead (see [`crate::handoff`]). Which protocol a
//! blob's table 3 carries is fixed by the image entry that runs
//! plus the host's birth record, never selected by inspecting
//! magic. The ordinary entry reads table 3 only as the
//! tool-defined ordinary packet and the successor entry only
//! as HLISUC01; wrong-protocol bytes in either reader are a
//! terminal named refusal with no fallback decode.
//!
//! This schema is distinct from the tool-defined ordinary
//! initialization packet. The distinct magic prevents either
//! codec from interpreting the other protocol's bytes.
//!
//! The packet carries exactly the three launch-bound values the
//! successor entry needs before InitialImage redemption: the
//! expected configuration digest, the bounded redemption bytes,
//! and whether a predecessor state deposit is expected. It is
//! data only: decoding grants no admission, mapping, or
//! execution authority. Admission remains the coordinator-side
//! watched-birth `InitialImageAdmission` consumption; the
//! expected digest must additionally match the delivered
//! configuration bytes under the transport's own check before
//! any decode of that configuration.
//!
//! Layout (all integers little-endian, matching [`crate::handoff`]):
//!
//! ```text
//! offset  size  field
//! 0       8     magic "HLISUC01"
//! 8       2     version (1)
//! 10      2     flags (bit 0: state expected; all other bits 0)
//! 12      2     redemption length (1..=256)
//! 14      2     reserved, must be 0
//! 16      32    expected configuration digest (SHA-256 bytes)
//! 48      N     redemption bytes
//! ```
//!
//! The total packet length is exactly `48 + redemption length`
//! and never exceeds the table-3 bound of 4096 bytes. This module
//! allocates nothing, dereferences no numeric address, and
//! invokes no syscall.

/// Packet magic at offset 0.
pub const MAGIC: [u8; 8] = *b"HLISUC01";
/// Only supported packet revision; no fallback decoding occurs.
pub const VERSION: u16 = 1;
/// Fixed header length before the redemption bytes.
pub const HEADER_LEN: usize = 48;
/// Flag bit: a predecessor state deposit is expected for this birth.
/// A clear bit only says no deposit is expected; it does not by
/// itself prove a first-image birth, and a successor entry must
/// refuse it rather than reinterpret it as an ordinary birth.
pub const FLAG_STATE_EXPECTED: u16 = 1 << 0;
/// Every flag bit defined by this revision.
const KNOWN_FLAGS: u16 = FLAG_STATE_EXPECTED;
/// Redemption bound, mirroring the InitialImage transport bound.
pub const MAX_REDEMPTION_LEN: usize = 256;
/// Largest complete packet (the HLSCAL01 table-3 bound).
pub const MAX_PACKET_LEN: usize = 4096;

/// Exact encoded length for a redemption of `redemption_len`
/// bytes, or `None` when that length is inadmissible.
pub const fn encoded_len(redemption_len: usize) -> Option<usize> {
    if redemption_len == 0 || redemption_len > MAX_REDEMPTION_LEN {
        return None;
    }
    // 48 + 256 <= 4096 always; kept checked so the bound lives in
    // exactly one place if either constant ever moves.
    match HEADER_LEN.checked_add(redemption_len) {
        Some(total) if total <= MAX_PACKET_LEN => Some(total),
        _ => None,
    }
}

/// Packet decode/encode failure. Numeric validation only; no
/// variant grants or withholds physical authority by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Magic, fixed lengths, or exact total length disagree.
    Format,
    /// Version field is not [`VERSION`].
    Version,
    /// Reserved field is nonzero.
    Reserved,
    /// A flag bit outside this revision's defined set is set.
    Flags,
    /// Redemption length is zero or above [`MAX_REDEMPTION_LEN`],
    /// or the output buffer cannot hold the encoded packet.
    Bounds,
}

/// Decoded borrowed view of one exact packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitPacket<'a> {
    flags: u16,
    expected_config_digest: [u8; 32],
    redemption: &'a [u8],
}

impl<'a> InitPacket<'a> {
    /// Whether this birth is a successor expecting a predecessor
    /// state deposit (flag bit 0).
    pub fn state_expected(&self) -> bool {
        self.flags & FLAG_STATE_EXPECTED != 0
    }

    /// Expected SHA-256 of the exact canonical configuration
    /// bytes, as carried. Bytes are compared, never recomputed
    /// here; hashing the delivered configuration is the
    /// transport's existing check.
    pub fn expected_config_digest(&self) -> [u8; 32] {
        self.expected_config_digest
    }

    /// Bounded launcher-defined redemption bytes, verbatim.
    pub fn redemption(&self) -> &'a [u8] {
        self.redemption
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, Error> {
    let bytes = packet.get(offset..offset + 2).ok_or(Error::Format)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Decode and fully validate one exact packet. Trailing bytes,
/// unknown flags, and nonzero reserved fields are refusals, not
/// ignored extensions.
pub fn decode(packet: &[u8]) -> Result<InitPacket<'_>, Error> {
    if packet.len() < HEADER_LEN || packet.len() > MAX_PACKET_LEN {
        return Err(Error::Format);
    }
    if packet[..8] != MAGIC {
        return Err(Error::Format);
    }
    if read_u16(packet, 8)? != VERSION {
        return Err(Error::Version);
    }
    let flags = read_u16(packet, 10)?;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(Error::Flags);
    }
    let redemption_len = usize::from(read_u16(packet, 12)?);
    if read_u16(packet, 14)? != 0 {
        return Err(Error::Reserved);
    }
    let total = encoded_len(redemption_len).ok_or(Error::Bounds)?;
    if packet.len() != total {
        return Err(Error::Format);
    }
    let mut expected_config_digest = [0u8; 32];
    expected_config_digest.copy_from_slice(&packet[16..48]);
    Ok(InitPacket {
        flags,
        expected_config_digest,
        redemption: &packet[HEADER_LEN..total],
    })
}

/// Encode one packet into `out`, returning its exact length.
/// The same validations as [`decode`] apply to the inputs, so a
/// host producer cannot emit a packet the entry would refuse.
pub fn encode_into(
    out: &mut [u8],
    flags: u16,
    expected_config_digest: &[u8; 32],
    redemption: &[u8],
) -> Result<usize, Error> {
    if flags & !KNOWN_FLAGS != 0 {
        return Err(Error::Flags);
    }
    let total = encoded_len(redemption.len()).ok_or(Error::Bounds)?;
    let out = out.get_mut(..total).ok_or(Error::Bounds)?;
    out[..8].copy_from_slice(&MAGIC);
    out[8..10].copy_from_slice(&VERSION.to_le_bytes());
    out[10..12].copy_from_slice(&flags.to_le_bytes());
    // Bounded by encoded_len above (<= 256), so the cast is exact;
    // kept checked rather than narrowing silently.
    let redemption_len = u16::try_from(redemption.len()).map_err(|_| Error::Bounds)?;
    out[12..14].copy_from_slice(&redemption_len.to_le_bytes());
    out[14..16].copy_from_slice(&0u16.to_le_bytes());
    out[16..48].copy_from_slice(expected_config_digest);
    out[HEADER_LEN..total].copy_from_slice(redemption);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: [u8; 32] = [0x5a; 32];

    fn encoded(flags: u16, redemption: &[u8]) -> ([u8; MAX_PACKET_LEN], usize) {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let len = encode_into(&mut buf, flags, &DIGEST, redemption).unwrap();
        (buf, len)
    }

    #[test]
    fn round_trip_successor_and_first_image() {
        let (buf, len) = encoded(FLAG_STATE_EXPECTED, b"launch-nonce-1");
        let packet = decode(&buf[..len]).unwrap();
        assert!(packet.state_expected());
        assert_eq!(packet.expected_config_digest(), DIGEST);
        assert_eq!(packet.redemption(), b"launch-nonce-1");
        assert_eq!(len, HEADER_LEN + 14);

        let (buf, len) = encoded(0, b"n");
        let packet = decode(&buf[..len]).unwrap();
        assert!(!packet.state_expected());
        assert_eq!(packet.redemption(), b"n");
    }

    #[test]
    fn round_trip_max_redemption() {
        let redemption = [0xabu8; MAX_REDEMPTION_LEN];
        let (buf, len) = encoded(FLAG_STATE_EXPECTED, &redemption);
        assert_eq!(len, HEADER_LEN + MAX_REDEMPTION_LEN);
        assert_eq!(decode(&buf[..len]).unwrap().redemption(), redemption);
    }

    #[test]
    fn refuses_bad_magic_version_reserved_flags() {
        let (mut buf, len) = encoded(0, b"x");
        buf[0] = b'X';
        assert_eq!(decode(&buf[..len]), Err(Error::Format));

        let (mut buf, len) = encoded(0, b"x");
        buf[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(decode(&buf[..len]), Err(Error::Version));

        let (mut buf, len) = encoded(0, b"x");
        buf[14] = 1;
        assert_eq!(decode(&buf[..len]), Err(Error::Reserved));

        let (mut buf, len) = encoded(0, b"x");
        buf[10..12].copy_from_slice(&0x8000u16.to_le_bytes());
        assert_eq!(decode(&buf[..len]), Err(Error::Flags));

        let mut out = [0u8; 64];
        assert_eq!(encode_into(&mut out, 0x2, &DIGEST, b"x"), Err(Error::Flags));
    }

    #[test]
    fn refuses_bad_lengths() {
        assert_eq!(encoded_len(0), None);
        assert_eq!(encoded_len(MAX_REDEMPTION_LEN + 1), None);
        assert_eq!(
            encoded_len(MAX_REDEMPTION_LEN),
            Some(HEADER_LEN + MAX_REDEMPTION_LEN)
        );

        let mut out = [0u8; MAX_PACKET_LEN];
        assert_eq!(encode_into(&mut out, 0, &DIGEST, b""), Err(Error::Bounds));
        let too_long = [0u8; MAX_REDEMPTION_LEN + 1];
        assert_eq!(
            encode_into(&mut out, 0, &DIGEST, &too_long),
            Err(Error::Bounds)
        );
        let mut short = [0u8; HEADER_LEN];
        assert_eq!(
            encode_into(&mut short, 0, &DIGEST, b"abcd"),
            Err(Error::Bounds)
        );

        // Truncated and trailing-extra packets are format errors:
        // the packet length must be exact.
        let (buf, len) = encoded(0, b"abcd");
        assert_eq!(decode(&buf[..len - 1]), Err(Error::Format));
        assert_eq!(decode(&buf[..len + 1]), Err(Error::Format));
        assert_eq!(decode(&buf[..HEADER_LEN - 1]), Err(Error::Format));

        // Declared length zero with an exact-fit buffer still refuses.
        let (mut buf, len) = encoded(0, b"abcd");
        buf[12..14].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(decode(&buf[..len]), Err(Error::Bounds));
    }

    #[test]
    fn every_truncated_prefix_is_refused_without_panicking() {
        let max_redemption = [0xcd; MAX_REDEMPTION_LEN];
        for redemption in [&b"x"[..], b"launch-nonce-1", &max_redemption] {
            let (buf, len) = encoded(FLAG_STATE_EXPECTED, redemption);
            for prefix in 0..len {
                assert!(
                    decode(&buf[..prefix]).is_err(),
                    "prefix {prefix} of {len} unexpectedly decoded"
                );
            }
        }
    }

    #[test]
    fn header_bit_flips_are_named_refusals() {
        let (valid, len) = encoded(0, b"launch-nonce-1");
        for byte in 0..16 {
            for bit in 0..8 {
                let mut packet = valid;
                packet[byte] ^= 1 << bit;
                let result = decode(&packet[..len]);
                match byte {
                    0..=7 => assert_eq!(result, Err(Error::Format), "byte {byte} bit {bit}"),
                    8 | 9 => assert_eq!(result, Err(Error::Version), "byte {byte} bit {bit}"),
                    10 if bit == 0 => {
                        assert!(result.unwrap().state_expected(), "byte {byte} bit {bit}")
                    }
                    10 | 11 => assert_eq!(result, Err(Error::Flags), "byte {byte} bit {bit}"),
                    12 => assert_eq!(result, Err(Error::Format), "byte {byte} bit {bit}"),
                    13 => assert_eq!(result, Err(Error::Bounds), "byte {byte} bit {bit}"),
                    14 | 15 => assert_eq!(result, Err(Error::Reserved), "byte {byte} bit {bit}"),
                    _ => unreachable!(),
                }
            }
        }
    }

    #[test]
    fn refuses_declared_zero_and_257_with_exact_fit_buffers() {
        let (mut zero, _) = encoded(0, b"abcd");
        zero[12..14].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(decode(&zero[..HEADER_LEN]), Err(Error::Bounds));

        let (mut oversized, _) = encoded(0, b"abcd");
        oversized[12..14].copy_from_slice(&257u16.to_le_bytes());
        assert_eq!(decode(&oversized[..HEADER_LEN + 257]), Err(Error::Bounds));
    }

    #[test]
    fn inert_probe_packet_is_not_admitted() {
        // The stage-1a probe placeholder is preparation-only data,
        // never an admitted init packet.
        assert!(decode(b"PREPARATION_ONLY_NOT_HLIINIT1").is_err());
    }
}
