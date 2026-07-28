//! SHA-1, HMAC-SHA-1 and base64, as required by the `known_hosts` format.
//!
//! OpenSSH hashes a host name with HMAC-SHA-1 keyed by a per-line random salt,
//! so verifying a hashed entry needs SHA-1 whatever the rest of the stack uses.
//! Both primitives are implemented here rather than pulled in as dependencies,
//! and both are covered by the published RFC 3174 and RFC 2202 vectors.

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Computes the SHA-1 digest of `input`.
#[must_use]
#[expect(
    clippy::many_single_char_names,
    reason = "a..e are the working variable names RFC 3174 section 6.1 gives the SHA-1 \
              compression function; renaming them would break a line-by-line audit \
              against the published algorithm"
)]
pub fn sha1(input: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut padded = input.to_vec();
    let bit_length = (input.len() as u64).wrapping_mul(8);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 80];
        for (index, block) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        }
        for index in 16..80 {
            let value = words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16];
            words[index] = value.rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in words.iter().enumerate() {
            let (mixed, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(mixed)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut digest = [0u8; 20];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Computes HMAC-SHA-1 of `message` under `key`, per RFC 2104.
#[must_use]
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..20].copy_from_slice(&sha1(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + message.len());
    let mut outer = Vec::with_capacity(BLOCK + 20);
    for byte in block {
        inner.push(byte ^ 0x36);
        outer.push(byte ^ 0x5c);
    }
    inner.extend_from_slice(message);
    outer.extend_from_slice(&sha1(&inner));
    sha1(&outer)
}

/// Encodes `input` as standard base64.
///
/// `pad` selects whether the output carries `=` padding; OpenSSH prints a
/// SHA-256 fingerprint without it and a `known_hosts` salt with it.
#[must_use]
pub fn base64_encode(input: &[u8], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let byte0 = u32::from(chunk[0]);
        let byte1 = chunk.get(1).copied().map_or(0, u32::from);
        let byte2 = chunk.get(2).copied().map_or(0, u32::from);
        let packed = (byte0 << 16) | (byte1 << 8) | byte2;
        let indices = [
            (packed >> 18) & 0x3f,
            (packed >> 12) & 0x3f,
            (packed >> 6) & 0x3f,
            packed & 0x3f,
        ];
        let emitted = chunk.len() + 1;
        for index in indices.iter().take(emitted) {
            out.push(char::from(BASE64_ALPHABET[*index as usize]));
        }
        if pad {
            for _ in emitted..4 {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes standard base64, accepting an optionally padded input.
///
/// Returns `None` for any character outside the alphabet, for a stray `=` in the
/// middle of the input, and for a trailing group of a single character, which
/// can never encode a whole byte.
#[must_use]
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let trimmed = input.trim_end_matches('=');
    if trimmed.contains('=') {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() / 4 * 3);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for character in trimmed.bytes() {
        // `position` over a 64-entry table can only yield 0..=63, so the
        // conversion never actually rejects; keeping it fallible means an
        // unexpected alphabet size fails the decode closed rather than
        // truncating a sextet.
        let value = BASE64_ALPHABET
            .iter()
            .position(|&entry| entry == character)
            .and_then(|index| u32::try_from(index).ok())?;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let byte = u8::try_from((accumulator >> bits) & 0xff).ok()?;
            out.push(byte);
        }
    }
    if bits >= 6 || (accumulator & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}
