use asn1_der::{Asn1DerError, Asn1DerErrorVariant, typed::{DerDecodable, DerEncodable, Integer, Sequence}};

use crate::cert::{Algorithm, Prime};

pub struct EcdsaSigValue<'a> {
    r: Int<'a>,
    s: Int<'a>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct Int<'a>(&'a [u8]);

impl DerEncodable for Int<'_> {
    fn encode<S: asn1_der::Sink>(&self, sink: &mut S) -> Result<(), Asn1DerError> {
        Integer::write(self.0, false, sink)
    }
}

impl<'a> EcdsaSigValue<'a> {
    pub fn new(r: &'a [u8], s: &'a [u8]) -> Self {
        Self { r: Int(r), s: Int(s) }
    }
}

impl<'a> DerEncodable for EcdsaSigValue<'a> {
    fn encode<S: asn1_der::Sink>(&self, sink: &mut S) -> Result<(), Asn1DerError> {
        Sequence::write(&[self.r, self.s], sink)
    }
}

pub enum ObjectIdentifier {
    /// `id-ecPublicKey`
    IdEcPublicKey,
    /// `prime256v1`
    Prime256v1
}

impl<'a> DerDecodable<'a> for ObjectIdentifier {
    fn load(object: asn1_der::DerObject<'a>) -> Result<Self, Asn1DerError> {
        if object.tag() == 0x06 {
            todo!();
        } else {
            Err(Asn1DerError::new(Asn1DerErrorVariant::InvalidData("expected object id tag 0x06")))
        }
    }
}

impl<'a> DerDecodable<'a> for Algorithm {
    fn load(object: asn1_der::DerObject<'a>) -> Result<Self, Asn1DerError> {
        let seq = Sequence::load(object)?;
        let alg_obj_id = seq.get_as::<ObjectIdentifier>(0)?;
        match alg_obj_id {
            ObjectIdentifier::IdEcPublicKey => {
                let prime_obj_id = seq.get_as::<ObjectIdentifier>(1)?;
                if let ObjectIdentifier::Prime256v1 = prime_obj_id {
                    Ok(Algorithm::IdEcPublicKey(Prime::Prime256v1))
                } else {
                    Err(Asn1DerError::new(Asn1DerErrorVariant::Unsupported("prime object id")))
                }
                
            }
            _ => Err(Asn1DerError::new(Asn1DerErrorVariant::Unsupported("algorithm object id"))),
        }
    }
}

pub struct PublicKey {
    pub algorithm: Algorithm,
    pub data: Vec<u8>,
}

impl<'a> DerDecodable<'a> for PublicKey {
    fn load(object: asn1_der::DerObject<'a>) -> Result<Self, Asn1DerError> {
        let seq = Sequence::load(object)?;
        let algorithm = seq.get_as(0)?;

        Ok(PublicKey {
            algorithm,
            data: vec![],
        })
    }
}