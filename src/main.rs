use color_eyre::eyre::eyre;
use log::{debug, info, warn};
use once_cell::sync::OnceCell;
use serde_cose::sig::Sig;
use std::{convert::TryFrom, fmt};
use structopt::StructOpt;
use x509_parser::{der_parser::oid, oid_registry::OidRegistry, prelude::*};

use crate::{
    cert::{Algorithm, Prime, TrustList},
    dcc::{
        load_sign1,
        valuesets::{EhnData, ValueSet},
        CertPayload,
    },
    json::Loadable,
};

pub mod b45;
pub mod cert;
pub mod cwt;
pub mod dcc;
pub mod json;
//pub mod sig;

static OID_REGISTRY: OnceCell<OidRegistry> = OnceCell::new();
static EHN_DATA: OnceCell<EhnData> = OnceCell::new();
static TRUSTLIST: OnceCell<TrustList> = OnceCell::new();

#[derive(Debug, StructOpt)]
struct Args {
    #[structopt(long)]
    json: bool,
    #[structopt(default_value = "-")]
    file: String,
}

struct CertSubject<'a>(&'a X509Name<'a>);

impl fmt::Debug for CertSubject<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let oid_registry = OID_REGISTRY.get().unwrap();
        let mut debug = f.debug_struct("X509Name");

        for key in self.0.iter_attributes() {
            match (oid_registry.get(&key.attr_type), key.attr_value.as_str()) {
                (Some(name), Ok(value)) => {
                    debug.field(name.sn(), &value);
                }
                (Some(name), Err(_)) => {
                    debug.field(name.sn(), &"???");
                }
                (None, Ok(value)) => {
                    let name = format!("oid_{}", key.attr_type);
                    debug.field(&name, &value);
                }
                (None, Err(_)) => {
                    let name = format!("oid_{}", key.attr_type);
                    debug.field(&name, &"???");
                }
            }
        }
        debug.finish()
    }
}

fn main() -> color_eyre::Result<()> {
    // Setup logging and panic hooks
    color_eyre::install()?;
    pretty_env_logger::formatted_builder()
        .filter(Some("dcc_decode"), log::LevelFilter::Debug)
        .init();

    // Load CLI args
    let args = Args::from_args();

    // Populate global OID registry
    let mut oid_registry = OidRegistry::default().with_crypto().with_x509();
    oid_registry.insert(oid!(2.5.4 .97), ("organizationIdentifier", ""));
    oid_registry.insert(
        oid!(2.5.4 .5),
        ("serialNumber", "Serial number attribute type"),
    );
    OID_REGISTRY.set(oid_registry).unwrap();

    // Populate eHN value sets
    let ehn_data = EhnData {
        vaccine_prophylaxis: ValueSet::load("ehn-dcc-valuesets/vaccine-prophylaxis.json"),
        disease_agent_targeted: ValueSet::load("ehn-dcc-valuesets/disease-agent-targeted.json"),
        vaccine_mah_manf: ValueSet::load("ehn-dcc-valuesets/vaccine-mah-manf.json"),
        vaccine_medicinal_product: ValueSet::load(
            "ehn-dcc-valuesets/vaccine-medicinal-product.json",
        ),
    };
    EHN_DATA.set(ehn_data).unwrap();

    // Populate cert store
    if let Some(trustlist) = TrustList::load("trustlist.json") {
        TRUSTLIST.set(trustlist).unwrap();
    }

    // Load certificate data
    let mut buf = String::new();

    if args.file == "-" {
        std::io::stdin().read_line(&mut buf)?;
    } else {
        buf = std::fs::read_to_string(&args.file)?;
    }

    let sign1 = load_sign1(&buf)?;
    let b64_kid = base64::encode(sign1.kid());
    info!("Well-formed COSE certificate (kid='{}')", b64_kid);

    let v = CertPayload::try_from(&sign1)?;
    info!("Well-formed Digital-Covid-Certificate");

    if args.json {
        let jout = serde_json::to_string(&v.health_claim.cert)?;
        println!("{}", jout);
    } else {
        println!("{:#?}", v);
    }

    let signature = sign1.signature.clone();

    if let Some(cert) = TRUSTLIST
        .get()
        .and_then(|t| t.certificates.iter().find(|&c| c.kid == b64_kid))
    {
        info!("Found certificate with matching kid in trustlist");

        // Transform COSE_Sign1 into Signature1
        let sig = Sig::from(sign1);
        let message = serde_cbor::to_vec(&sig)?;
        debug!("Signature1 encoding successful");

        // Read the X.509 certificate
        let sigbytes = base64::decode(&cert.raw_data)?;
        let (_, sigcert) = parse_x509_certificate(&sigbytes)?;
        debug!("Loaded issuer X.509 certificate");

        let subject = &sigcert.tbs_certificate.subject;
        if let Some(name) = subject
            .iter_common_name()
            .next()
            .and_then(|name| name.attr_value.as_str().ok())
        {
            info!("subject common name: {:?}", name);
        }
        // println!("{:#?}", CertSubject(subject));

        // Check the signature algorithm
        let sigpki = &sigcert.tbs_certificate.subject_pki;
        let alg = cert::get_pk_sig_algorithm(sigpki)?;
        debug!("found signature algorithm: {:?}", alg);

        if Algorithm::IdEcPublicKey(Prime::Prime256v1) == alg {
            let pubkey = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_FIXED,
                &sigpki.subject_public_key.data,
            );

            pubkey
                .verify(&message, &signature)
                .map_err(|_e| eyre!("Verification failed"))?;
            info!("Verified OK");
        } else {
            warn!("Unknown signature algorithm");
        }

        // // FIXME: Write out relevant keys as files
        // let dir = std::env::current_dir()?;
        // println!("Writing files ({})", dir.display());
        // std::fs::write("message.bin", &message)?;
        // std::fs::write("signature.bin", &signature)?;

        // // Write out signature as `EcdsaSigValue`
        // let ecdsa_sig = EcdsaSigValue::new(&signature[..32], &signature[32..]);
        // let mut buf: Vec<u8> = Vec::new();
        // ecdsa_sig.encode(&mut buf)?;
        // std::fs::write("ecdsa-sig-value.bin", &buf)?;
    } else {
        warn!("Did not find certificate with matching kid")
    }

    Ok(())
}
