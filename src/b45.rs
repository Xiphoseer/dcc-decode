use std::{convert::TryFrom, error::Error, fmt};

#[derive(Debug)]
pub enum Base45Error {
    Unimplemented,
    InvalidChar(u8),
    InvalidTriple(u32),
}

impl Error for Base45Error {}
impl fmt::Display for Base45Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unimplemented => write!(f, "Base45Error"),
            Self::InvalidChar(c) => write!(f, "Invalid character: {}", c),
            Self::InvalidTriple(t) => write!(f, "Invalid sum: {}", t),
        }
    }
}

pub fn base45_cval(input: u8) -> Result<u32, Base45Error> {
    match input {
        b'0'..=b'9' => Ok(u32::from(input - b'0')),
        b'A'..=b'Z' => Ok(u32::from(input - b'A') + 10),
        b' ' => Ok(36),
        b'$' => Ok(37),
        b'%' => Ok(38),
        b'*' => Ok(39),
        b'+' => Ok(40),
        b'-' => Ok(41),
        b'.' => Ok(42),
        b'/' => Ok(43),
        b':' => Ok(44),
        _ => Err(Base45Error::InvalidChar(input)),
    }
}

pub fn base45_cdec([c, d, e]: [u8; 3]) -> Result<[u8; 2], Base45Error> {
    let c = base45_cval(c)?;
    let d = base45_cval(d)?;
    let e = base45_cval(e)?;

    let sum = c + 45 * d + 45 * 45 * e;
    let r = u16::try_from(sum).map_err(|_| Base45Error::InvalidTriple(sum))?;
    Ok(r.to_le_bytes())
}

#[allow(clippy::many_single_char_names)]
pub fn base45_decode(input: &str) -> Result<Vec<u8>, Base45Error> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 2 / 3 + 1);

    let mut triples = bytes.chunks_exact(3);
    while let Some(triple) = triples.next() {
        println!("{}", std::str::from_utf8(triple).unwrap());
        let c = triple[0];
        let d = triple[1];
        let e = triple[2];

        let [a, b] = base45_cdec([c, d, e])?;
        out.push(a);
        out.push(b);
    }
    if let [_c, _d] = triples.remainder() {
        return Err(Base45Error::Unimplemented);
    }

    Ok(out)
}
