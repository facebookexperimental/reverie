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
//! The packet carries exactly the four launch-bound values the
//! successor entry needs before InitialImage redemption: the
//! expected configuration digest, the expected state digest,
//! the bounded redemption bytes, and whether a predecessor
//! state deposit is expected. It is data only: decoding grants
//! no admission, mapping, or execution authority. Admission
//! remains the coordinator-side watched-birth
//! `InitialImageAdmission` consumption. The expected digests
//! must additionally match the delivered configuration and
//! predecessor-state bytes before either is decoded; for state,
//! a future successor entry must perform that hash comparison
//! before `ExecState::decode`. That entry does not exist yet.
//!
//! Layout (all integers little-endian, matching [`crate::handoff`]):
//!
//! ```text
//! offset  size  field
//! 0       8     magic "HLISUC01"
//! 8       2     version (2)
//! 10      2     flags (bit 0: state expected; all other bits 0)
//! 12      2     redemption length (1..=256)
//! 14      2     reserved, must be 0
//! 16      32    expected configuration digest (SHA-256 bytes)
//! 48      32    expected state digest (SHA-256 bytes; all-zero
//!               iff the state-expected flag is clear)
//! 80      N     redemption bytes
//! ```
//!
//! The total packet length is exactly `80 + redemption length`
//! and never exceeds the table-3 bound of 4096 bytes. This module
//! allocates nothing, dereferences no numeric address, and
//! invokes no syscall.

/// Packet magic at offset 0.
pub const MAGIC: [u8; 8] = *b"HLISUC01";
/// Only supported packet revision; no fallback decoding occurs.
/// Version 1 packets are refused: this revision is the first
/// with a producer, and the state digest is not optional.
pub const VERSION: u16 = 2;
/// Fixed header length before the redemption bytes.
pub const HEADER_LEN: usize = 80;
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
    // 80 + 256 <= 4096 always; kept checked so the bound lives in
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
    /// A flag bit outside this revision's defined set is set, or
    /// the state digest is not all-zero exactly when the
    /// state-expected flag is clear (nonzero while clear, or
    /// all-zero while set).
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
    expected_state_digest: [u8; 32],
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

    /// Expected SHA-256 of the exact predecessor state bytes
    /// the coordinator will deliver, as carried. All zero iff
    /// no state deposit is expected. A future successor entry
    /// must hash the delivered state and compare it with this
    /// digest before `ExecState::decode`; that consumer check
    /// is not implemented in this slice.
    pub fn expected_state_digest(&self) -> [u8; 32] {
        self.expected_state_digest
    }

    /// Bounded launcher-defined redemption bytes, verbatim.
    pub fn redemption(&self) -> &'a [u8] {
        self.redemption
    }
}

/// A decoded HLISUC01 packet accepted specifically for the
/// successor route. Unlike [`InitPacket`], this view exists
/// only when a predecessor state deposit is expected. It is
/// data only and grants no admission, mapping, or execution
/// authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuccessorInitPacket<'a> {
    packet: InitPacket<'a>,
}

impl<'a> SuccessorInitPacket<'a> {
    /// The exact decoded packet view, including its
    /// state-expected flag.
    pub fn packet(&self) -> InitPacket<'a> {
        self.packet
    }

    /// Expected SHA-256 of the exact canonical configuration bytes.
    pub fn expected_config_digest(&self) -> [u8; 32] {
        self.packet.expected_config_digest()
    }

    /// Expected SHA-256 of the exact predecessor state bytes.
    pub fn expected_state_digest(&self) -> [u8; 32] {
        self.packet.expected_state_digest()
    }

    /// Bounded launcher-defined redemption bytes, verbatim.
    pub fn redemption(&self) -> &'a [u8] {
        self.packet.redemption()
    }
}

/// Failure to decode a packet specifically for the successor route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuccessorInitPacketError {
    /// The bytes are not an exact HLISUC01 packet.
    Packet(Error),
    /// The packet is valid HLISUC01, but its state-expected flag
    /// is clear and therefore it is not a successor packet.
    StateNotExpected,
}

impl SuccessorInitPacketError {
    /// Stable refusal name used by host and guest diagnostics.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Packet(Error::Format) => "init_packet_format",
            Self::Packet(Error::Version) => "init_packet_version",
            Self::Packet(Error::Reserved) => "init_packet_reserved",
            Self::Packet(Error::Flags) => "init_packet_flags",
            Self::Packet(Error::Bounds) => "init_packet_bounds",
            Self::StateNotExpected => "init_packet_state_not_expected",
        }
    }
}

impl From<Error> for SuccessorInitPacketError {
    fn from(error: Error) -> Self {
        Self::Packet(error)
    }
}

/// Decode one exact HLISUC01 packet for the successor route.
/// The route is selected by the caller, never by inspecting
/// magic; this function then refuses a valid packet whose
/// state-expected flag is clear rather than reinterpreting it
/// as a first-image packet.
pub fn decode_successor(
    packet: &[u8],
) -> Result<SuccessorInitPacket<'_>, SuccessorInitPacketError> {
    let packet = decode(packet)?;
    if !packet.state_expected() {
        return Err(SuccessorInitPacketError::StateNotExpected);
    }
    Ok(SuccessorInitPacket { packet })
}

fn state_digest_matches_flag(flags: u16, expected_state_digest: &[u8; 32]) -> bool {
    (flags & FLAG_STATE_EXPECTED != 0) != (*expected_state_digest == [0u8; 32])
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, Error> {
    let bytes = packet.get(offset..offset + 2).ok_or(Error::Format)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Decode and fully validate one exact packet. Trailing bytes,
/// unknown flags, and nonzero reserved fields are refusals, not
/// ignored extensions.
pub fn decode(packet: &[u8]) -> Result<InitPacket<'_>, Error> {
    // The version is named before the fixed-length checks so a
    // version 1 packet (whose 48-byte header is shorter than
    // this revision's) refuses as `Version`, never as a generic
    // truncation. Ten bytes cover magic plus version without
    // slicing past the input.
    if packet.len() < 10 || packet.len() > MAX_PACKET_LEN {
        return Err(Error::Format);
    }
    if packet[..8] != MAGIC {
        return Err(Error::Format);
    }
    if read_u16(packet, 8)? != VERSION {
        return Err(Error::Version);
    }
    if packet.len() < HEADER_LEN {
        return Err(Error::Format);
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
    let mut expected_state_digest = [0u8; 32];
    expected_state_digest.copy_from_slice(&packet[48..80]);
    if !state_digest_matches_flag(flags, &expected_state_digest) {
        return Err(Error::Flags);
    }
    Ok(InitPacket {
        flags,
        expected_config_digest,
        expected_state_digest,
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
    expected_state_digest: &[u8; 32],
    redemption: &[u8],
) -> Result<usize, Error> {
    if flags & !KNOWN_FLAGS != 0 || !state_digest_matches_flag(flags, expected_state_digest) {
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
    out[48..80].copy_from_slice(expected_state_digest);
    out[HEADER_LEN..total].copy_from_slice(redemption);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: [u8; 32] = [0x5a; 32];
    const STATE_DIGEST: [u8; 32] = [0xa5; 32];
    const NO_STATE_DIGEST: [u8; 32] = [0; 32];

    fn state_digest_for(flags: u16) -> [u8; 32] {
        if flags & FLAG_STATE_EXPECTED != 0 {
            STATE_DIGEST
        } else {
            NO_STATE_DIGEST
        }
    }

    fn encoded(flags: u16, redemption: &[u8]) -> ([u8; MAX_PACKET_LEN], usize) {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let state_digest = state_digest_for(flags);
        let len = encode_into(&mut buf, flags, &DIGEST, &state_digest, redemption).unwrap();
        (buf, len)
    }

    #[test]
    fn round_trip_successor_and_first_image() {
        let (buf, len) = encoded(FLAG_STATE_EXPECTED, b"launch-nonce-1");
        let packet = decode(&buf[..len]).unwrap();
        assert!(packet.state_expected());
        assert_eq!(packet.expected_config_digest(), DIGEST);
        assert_eq!(packet.expected_state_digest(), STATE_DIGEST);
        assert_eq!(packet.redemption(), b"launch-nonce-1");
        assert_eq!(len, HEADER_LEN + 14);
        // Field placement is exact, not merely self-consistent:
        // state digest at 48..80, redemption from byte 80.
        assert_eq!(&buf[48..80], STATE_DIGEST);
        assert_eq!(&buf[80..len], b"launch-nonce-1");

        let (buf, len) = encoded(0, b"n");
        let packet = decode(&buf[..len]).unwrap();
        assert!(!packet.state_expected());
        assert_eq!(packet.expected_state_digest(), NO_STATE_DIGEST);
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
        buf[8..10].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(decode(&buf[..len]), Err(Error::Version));

        let (mut buf, len) = encoded(0, b"x");
        buf[14] = 1;
        assert_eq!(decode(&buf[..len]), Err(Error::Reserved));

        let (mut buf, len) = encoded(0, b"x");
        buf[10..12].copy_from_slice(&0x8000u16.to_le_bytes());
        assert_eq!(decode(&buf[..len]), Err(Error::Flags));

        let mut out = [0u8; 128];
        assert_eq!(
            encode_into(&mut out, 0x2, &DIGEST, &NO_STATE_DIGEST, b"x"),
            Err(Error::Flags)
        );
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
        assert_eq!(
            encode_into(&mut out, 0, &DIGEST, &NO_STATE_DIGEST, b""),
            Err(Error::Bounds)
        );
        let too_long = [0u8; MAX_REDEMPTION_LEN + 1];
        assert_eq!(
            encode_into(&mut out, 0, &DIGEST, &NO_STATE_DIGEST, &too_long),
            Err(Error::Bounds)
        );
        let mut short = [0u8; HEADER_LEN];
        assert_eq!(
            encode_into(&mut short, 0, &DIGEST, &NO_STATE_DIGEST, b"abcd"),
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
                        assert_eq!(result, Err(Error::Flags), "byte {byte} bit {bit}")
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
    fn refuses_v1_packets_as_version_at_both_size_bounds() {
        // Hand-built version 1 shape (48-byte header, no state
        // digest): the shortest v1 packet is below this
        // revision's header length and the longest above it;
        // both must name the version, with no fallback decode.
        for redemption_len in [1usize, MAX_REDEMPTION_LEN] {
            let mut packet = [0u8; 48 + MAX_REDEMPTION_LEN];
            packet[..8].copy_from_slice(&MAGIC);
            packet[8..10].copy_from_slice(&1u16.to_le_bytes());
            packet[10..12].copy_from_slice(&FLAG_STATE_EXPECTED.to_le_bytes());
            packet[12..14].copy_from_slice(&(redemption_len as u16).to_le_bytes());
            packet[16..48].copy_from_slice(&DIGEST);
            assert_eq!(
                decode(&packet[..48 + redemption_len]),
                Err(Error::Version),
                "redemption_len {redemption_len}"
            );
        }
    }

    #[test]
    fn refuses_nonzero_state_digest_when_no_state_is_expected() {
        // Every single nonzero state-digest byte refuses while
        // the flag is clear, on both the decode and encode side.
        let (valid, len) = encoded(0, b"x");
        for byte in 48..80 {
            let mut packet = valid;
            packet[byte] = 1;
            assert_eq!(decode(&packet[..len]), Err(Error::Flags), "byte {byte}");
        }
        let mut out = [0u8; MAX_PACKET_LEN];
        for byte in 0..32 {
            let mut one_byte_set = NO_STATE_DIGEST;
            one_byte_set[byte] = 1;
            assert_eq!(
                encode_into(&mut out, 0, &DIGEST, &one_byte_set, b"x"),
                Err(Error::Flags),
                "digest byte {byte}"
            );
        }
    }

    #[test]
    fn refuses_zero_state_digest_when_state_is_expected() {
        // Encode side: the reviewer's probe shape must not emit
        // an 81-byte successor packet with no state digest.
        let mut out = [0u8; MAX_PACKET_LEN];
        assert_eq!(
            encode_into(
                &mut out,
                FLAG_STATE_EXPECTED,
                &DIGEST,
                &NO_STATE_DIGEST,
                b"x"
            ),
            Err(Error::Flags)
        );

        // Decode side: hand-built equivalent bytes (a flag-clear
        // packet's flag set, leaving its digest all zero).
        let (mut packet, len) = encoded(0, b"x");
        packet[10..12].copy_from_slice(&FLAG_STATE_EXPECTED.to_le_bytes());
        assert_eq!(decode(&packet[..len]), Err(Error::Flags));

        // The same refusal applies when a valid successor
        // packet's carried digest is zeroed in place.
        let (mut packet, len) = encoded(FLAG_STATE_EXPECTED, b"x");
        packet[48..80].fill(0);
        assert_eq!(decode(&packet[..len]), Err(Error::Flags));
    }

    #[test]
    fn successor_packet_exposes_distinct_packet_facts() {
        let (packet, len) = encoded(FLAG_STATE_EXPECTED, b"birth-nonce");
        let decoded = decode_successor(&packet[..len]).unwrap();
        assert_eq!(decoded.expected_config_digest(), DIGEST);
        assert_eq!(decoded.expected_state_digest(), STATE_DIGEST);
        assert_eq!(decoded.redemption(), b"birth-nonce");
        assert!(decoded.packet().state_expected());

        for byte in [0, 31] {
            let mut state_digest = NO_STATE_DIGEST;
            state_digest[byte] = 1;
            let mut packet = [0u8; MAX_PACKET_LEN];
            let len = encode_into(
                &mut packet,
                FLAG_STATE_EXPECTED,
                &DIGEST,
                &state_digest,
                b"nonce",
            )
            .unwrap();
            let decoded = decode_successor(&packet[..len]).unwrap();
            assert_eq!(decoded.expected_state_digest(), state_digest, "byte {byte}");
        }
    }

    #[test]
    fn successor_packet_refuses_first_image_packet() {
        let (packet, len) = encoded(0, b"nonce");
        let error = decode_successor(&packet[..len]).unwrap_err();
        assert_eq!(error, SuccessorInitPacketError::StateNotExpected);
        assert_eq!(error.name(), "init_packet_state_not_expected");
    }

    #[test]
    fn successor_packet_maps_each_loader_error_to_its_name() {
        let (valid, len) = encoded(FLAG_STATE_EXPECTED, b"nonce");
        let named = |packet: &[u8]| decode_successor(packet).unwrap_err().name();

        let mut packet = valid;
        packet[0] ^= 1;
        assert_eq!(named(&packet[..len]), "init_packet_format");
        assert_eq!(
            named(b"PREPARATION_ONLY_NOT_HLIINIT1"),
            "init_packet_format"
        );

        let mut ordinary = [0u8; 128];
        ordinary[..8].copy_from_slice(b"HLIINIT1");
        assert_eq!(named(&ordinary), "init_packet_format");

        let mut packet = valid;
        packet[8..10].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(named(&packet[..len]), "init_packet_version");

        let mut packet = valid;
        packet[15] = 1;
        assert_eq!(named(&packet[..len]), "init_packet_reserved");

        let mut packet = valid;
        packet[10] |= 0b0000_0010;
        assert_eq!(named(&packet[..len]), "init_packet_flags");

        let mut packet = valid;
        packet[12..14].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(named(&packet[..HEADER_LEN]), "init_packet_bounds");
    }

    #[test]
    fn inert_probe_packet_is_not_admitted() {
        // The stage-1a probe placeholder is preparation-only data,
        // never an admitted init packet.
        assert!(decode(b"PREPARATION_ONLY_NOT_HLIINIT1").is_err());
    }
}
