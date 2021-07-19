use color_eyre::eyre::eyre;
use serde::Deserialize;
use x509_parser::{
    der_parser::{self, oid},
    oid_registry::OidRegistry,
    x509::SubjectPublicKeyInfo,
};

use crate::json::Loadable;

#[derive(Debug, Copy, Clone, Deserialize, PartialEq, Eq)]
pub enum CertType {
    DCC,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    pub certificate_type: CertType,
    pub country: String,
    pub kid: String,
    pub raw_data: String,
    pub signature: String,
    pub thumbprint: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustList {
    pub certificates: Vec<Certificate>,
}

impl Loadable for TrustList {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Prime {
    Prime256v1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Algorithm {
    IdEcPublicKey(Prime),
}

pub fn get_pk_sig_algorithm(sigpki: &SubjectPublicKeyInfo) -> color_eyre::Result<Algorithm> {
    //println!("Signature Certificate Public Key");
    let mut registry = OidRegistry::default().with_crypto().with_x509();
    registry.insert(
        oid!(1.2.840 .10045 .3 .1 .7),
        ("prime256v1", "256-bit Elliptic Curve Cryptography (ECC)"),
    );

    let e = registry.get(&sigpki.algorithm.algorithm);
    if let Some(entry) = e {
        //println!("alg-sn: {}", entry.sn());
        //println!("alg-description: {}", entry.description());
        if entry.sn() == "id-ecPublicKey" {
            let prime_ber = sigpki
                .algorithm
                .parameters
                .as_ref()
                .ok_or_else(|| eyre!("Expected prime parameter for 'id-ecPublicKey'"))?;
            let oid = prime_ber.as_oid()?;

            //println!("prime: {}", oid);
            let prime = if let Some(prime) = registry.get(oid) {
                //println!("prime-sn: {}", prime.sn());
                //println!("prime-description: {}", prime.description());
                if prime.sn() == "prime256v1" {
                    Ok(Prime::Prime256v1)
                } else {
                    Err(eyre!(
                        "Unsupported prime parameter '{}' ({}) for 'id-ecPublicKey'",
                        prime.sn(),
                        oid
                    ))
                }
            } else {
                Err(eyre!(
                    "Unknown prime parameter '{}' for 'id-ecPublicKey'",
                    oid
                ))
            }?;
            return Ok(Algorithm::IdEcPublicKey(prime));
        }
    }
    Err(eyre!("Unknown algorithm"))
}
