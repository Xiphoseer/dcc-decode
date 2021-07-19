use std::{convert::TryFrom, io::Read};

use chrono::{DateTime, NaiveDate, Utc};
use color_eyre::eyre::eyre;
use flate2::bufread::ZlibDecoder;
use log::debug;
use serde::{de::Error, Deserialize, Serialize};
use serde_cose::Sign1;

use self::valuesets::ValueSetEntry;

pub mod valuesets;

#[derive(Debug)]
pub struct CertPayload {
    pub issuer: String,
    pub expiration_time: DateTime<Utc>,
    pub issued_at: DateTime<Utc>,
    pub health_claim: HealthClaim,
}

pub fn load_sign1(buf: &str) -> color_eyre::Result<Sign1> {
    let text = buf.trim_end_matches('\n');
    let text = match text.strip_prefix("HC1:") {
        Some(tail) => tail,
        None => {
            return Err(eyre!("Expected a string that starts with 'HC1:'"));
        }
    };
    debug!("HealthCertificate v1 prefix valid");

    let decoded = base45::decode(text)?;
    debug!("Base45 decoding successful");

    let mut z = ZlibDecoder::new(&decoded[..]);
    let mut s = Vec::new();
    z.read_to_end(&mut s)?;
    debug!("zlib decoding successful");

    let sign1 = serde_cose::from_slice(&s)?;
    Ok(sign1)
}

impl TryFrom<&Sign1> for CertPayload {
    type Error = color_eyre::Report;

    fn try_from(sign1: &Sign1) -> color_eyre::Result<Self> {
        let v = serde_cbor::from_slice(&sign1.payload)?;
        debug!("CBOR certificate payload decoding successful");
        Ok(v)
    }
}

struct Timestamp(DateTime<Utc>);

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        chrono::serde::ts_seconds::deserialize(deserializer).map(Timestamp)
    }
}

struct CertVisitor;

impl<'de> serde::de::Visitor<'de> for CertVisitor {
    type Value = CertPayload;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a eHealth certification payload")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut issuer = None;
        let mut expiration_time: Option<Timestamp> = None;
        let mut issued_at: Option<Timestamp> = None;
        let mut health_claim = None;

        while let Some(key) = map.next_key()? {
            match key {
                1 => {
                    issuer = Some(map.next_value()?);
                }
                4 => {
                    expiration_time = Some(map.next_value()?);
                }
                6 => {
                    issued_at = Some(map.next_value()?);
                }
                -260 => {
                    health_claim = Some(map.next_value()?);
                }
                _ => {
                    println!("unknown field: {}", key);
                    let _: serde::de::IgnoredAny = map.next_value()?;
                }
            }
        }
        let issuer = issuer.ok_or_else(|| A::Error::missing_field("issuer (1)"))?;
        let expiration_time = expiration_time
            .ok_or_else(|| A::Error::missing_field("expiration_time (4)"))?
            .0;
        let issued_at = issued_at
            .ok_or_else(|| A::Error::missing_field("issued_at (6)"))?
            .0;
        let health_claim =
            health_claim.ok_or_else(|| A::Error::missing_field("health_claim (-260)"))?;

        Ok(CertPayload {
            issuer,
            expiration_time,
            issued_at,
            health_claim,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Vaccination {
    /// Disease or agent targeted
    ///
    ///  => COVID-19 (SARS-CoV or one of its variants)
    #[serde(rename = "tg", deserialize_with = "valuesets::deserialize_agent")]
    disease_agent_targeted: ValueSetEntry,
    /// vaccine or prophylaxis
    #[serde(rename = "vp", deserialize_with = "valuesets::deserialize_vaccine")]
    vaccine_or_prophylaxis: ValueSetEntry,
    /// vaccine product
    #[serde(
        rename = "mp",
        deserialize_with = "valuesets::deserialize_medicinal_product"
    )]
    medicinal_product: ValueSetEntry,
    /// marketing authorisation holder or manufacturer
    #[serde(rename = "ma", deserialize_with = "valuesets::deserialize_mah_manf")]
    manufacturer: ValueSetEntry,
    /// Number in a series of doses
    #[serde(rename = "dn")]
    dose_number: u32,
    /// The overall number of doses in the series
    #[serde(rename = "sd")]
    series_dose_number: u32,
    /// Date of vaccination
    #[serde(rename = "dt")]
    date: NaiveDate,
    /// Member State or third country in which the vaccine was administered
    #[serde(rename = "co")]
    country: String,
    /// Certificate issuer
    #[serde(rename = "is")]
    issuer: String,
    /// Unique certificate identifier
    #[serde(rename = "ci")]
    cert_identifier: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DigitalCovidCertificate {
    #[serde(rename = "v")]
    vaccine: Vec<Vaccination>,
    #[serde(rename = "dob")]
    date_of_birth: NaiveDate,
    #[serde(rename = "nam")]
    name: Name,
    #[serde(rename = "ver")]
    version: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Name {
    #[serde(rename = "fn")]
    first_name: String,
    #[serde(rename = "gn")]
    given_name: String,
    #[serde(rename = "fnt")]
    first_name_transliterated: String,
    #[serde(rename = "gnt")]
    given_name_transliterated: String,
}

#[derive(Debug)]
pub struct HealthClaim {
    pub cert: DigitalCovidCertificate,
}

struct CertInnerVisitor;

impl<'de> serde::de::Visitor<'de> for CertInnerVisitor {
    type Value = HealthClaim;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a eHealth certification payload inner")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut cert = None;

        while let Some(key) = map.next_key()? {
            match key {
                1 => {
                    cert = Some(map.next_value()?);
                }
                _ => {
                    println!("Unknown key: {}", key);
                    let _: serde::de::IgnoredAny = map.next_value()?;
                }
            }
        }
        let cert = cert.ok_or_else(|| A::Error::missing_field("cert (1)"))?;

        Ok(HealthClaim { cert })
    }
}

impl<'de> serde::Deserialize<'de> for HealthClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(CertInnerVisitor)
    }
}

impl<'de> serde::Deserialize<'de> for CertPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(CertVisitor)
    }
}
