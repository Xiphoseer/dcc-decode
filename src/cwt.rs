use std::{error::Error, fmt};

#[derive(Debug)]
pub enum CwtError {
    Unimplemented,
}

impl Error for CwtError {}
impl fmt::Display for CwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unimplemented => write!(f, "CwtError"),
        }
    }
}

pub fn cbor_byte(input: u8) -> Result<(u8, u8), CwtError> {
    let major = input >> 5;
    let info = input & 0b11111;
    Ok((major, info))
    //Err(CwtError::Unimplemented)
}
