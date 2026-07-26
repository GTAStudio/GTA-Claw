use ring::rand::{SecureRandom, SystemRandom};

use crate::error::{McpError, Result};

pub(crate) fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut output = [0_u8; N];
    SystemRandom::new()
        .fill(&mut output)
        .map_err(|_| McpError::Protocol("operating-system randomness is unavailable".into()))?;
    Ok(output)
}

pub(crate) fn uuid_v4() -> Result<String> {
    let mut bytes = bytes::<16>()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            output.push('-');
        }
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(output)
}
