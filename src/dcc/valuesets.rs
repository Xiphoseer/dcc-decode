use std::{collections::BTreeMap, fmt};

use chrono::NaiveDate;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{json::Loadable, EHN_DATA};

#[derive(Debug, Clone, Deserialize)]
pub struct Value {
    display: String,
    lang: String,
    active: bool,
    version: String,
    system: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValueSet {
    #[serde(rename = "valueSetId")]
    id: String,
    #[serde(rename = "valueSetDate")]
    date: NaiveDate,
    #[serde(rename = "valueSetValues")]
    values: BTreeMap<String, Value>,
}

impl Loadable for ValueSet {}

#[derive(Debug, Clone)]
pub struct ValueSetEntry {
    key: String,
    value: Option<&'static Value>,
}

impl Serialize for ValueSetEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.key.serialize(serializer)
    }
}

struct ValueSetVisitor(Option<&'static ValueSet>);

impl<'de> serde::de::Visitor<'de> for ValueSetVisitor {
    type Value = ValueSetEntry;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a value set key string")
    }

    fn visit_string<E>(self, key: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let mut value = None;
        if let Some(set) = self.0 {
            if let Some(entry) = set.values.get(&key) {
                value = Some(entry);
            }
        }
        Ok(ValueSetEntry { key, value })
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(v.to_string())
    }
}

fn deserialize_set_value<'de, D, F>(deserializer: D, f: F) -> Result<ValueSetEntry, D::Error>
where
    D: Deserializer<'de>,
    F: for<'r> FnOnce(&'r EhnData) -> &'r Option<ValueSet>,
{
    deserializer.deserialize_str(ValueSetVisitor(
        EHN_DATA.get().and_then(move |e| f(e).as_ref()),
    ))
}

pub fn deserialize_agent<'de, D>(deserializer: D) -> Result<ValueSetEntry, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_set_value(deserializer, |e| &e.disease_agent_targeted)
}

pub fn deserialize_vaccine<'de, D>(deserializer: D) -> Result<ValueSetEntry, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_set_value(deserializer, |e| &e.vaccine_prophylaxis)
}

pub fn deserialize_medicinal_product<'de, D>(deserializer: D) -> Result<ValueSetEntry, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_set_value(deserializer, |e| &e.vaccine_medicinal_product)
}

pub fn deserialize_mah_manf<'de, D>(deserializer: D) -> Result<ValueSetEntry, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_set_value(deserializer, |e| &e.vaccine_mah_manf)
}

#[derive(Default, Debug, Clone)]
pub struct EhnData {
    pub vaccine_prophylaxis: Option<ValueSet>,
    pub disease_agent_targeted: Option<ValueSet>,
    pub vaccine_mah_manf: Option<ValueSet>,
    pub vaccine_medicinal_product: Option<ValueSet>,
}

impl EhnData {}
