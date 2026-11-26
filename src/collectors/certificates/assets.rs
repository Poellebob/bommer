use std::collections::BTreeMap;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use x509_parser::{
    parse_x509_certificate,
    public_key::PublicKey,
    signature_algorithm::RsaSsaPssParams,
    x509::{AlgorithmIdentifier, SubjectPublicKeyInfo},
};

use crate::bom::document::Document;
use crate::collection::context::CollectionContext;
use crate::collectors::certificates::error::CertificateError;
use crate::collectors::certificates::types::{Assets, Observation};
use crate::path_encoding::path_text;

fn algorithm(
    algorithms: &mut BTreeMap<String, Value>,
    role: &str,
    name: &str,
    properties: Value,
) -> String {
    let reference = format!(
        "algorithm:sha256:{}",
        hex::encode(Sha256::digest(format!("{role}:{name}")))
    );
    algorithms.insert(reference.clone(), json!({"type":"cryptographic-asset","bom-ref":reference,"name":name,"cryptoProperties":{"assetType":"algorithm","algorithmProperties":properties},"properties":[{"name":"bommer:certificate:algorithm-role","value":role}]}));
    reference
}

fn signature_name(identifier: &AlgorithmIdentifier<'_>) -> &'static str {
    match identifier.algorithm.to_id_string().as_str() {
        "1.2.840.113549.1.1.2" => "MD2-RSA",
        "1.2.840.113549.1.1.4" => "MD5-RSA",
        "1.2.840.113549.1.1.5" => "SHA1-RSA",
        "1.2.840.113549.1.1.11" => "SHA256-RSA",
        "1.2.840.113549.1.1.12" => "SHA384-RSA",
        "1.2.840.113549.1.1.13" => "SHA512-RSA",
        "1.2.840.10040.4.3" => "DSA-SHA1",
        "2.16.840.1.101.3.4.3.2" => "DSA-SHA256",
        "1.2.840.10045.4.1" => "ECDSA-SHA1",
        "1.2.840.10045.4.3.2" => "ECDSA-SHA256",
        "1.2.840.10045.4.3.3" => "ECDSA-SHA384",
        "1.2.840.10045.4.3.4" => "ECDSA-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.2.840.113549.1.1.10" => {
            let Some(parameters) = identifier
                .parameters
                .as_ref()
                .and_then(|parameters| RsaSsaPssParams::try_from(parameters).ok())
            else {
                return "0";
            };
            let Ok(mask_generation_algorithm) = parameters.mask_gen_algorithm() else {
                return "0";
            };
            if parameters.trailer_field() != 1
                || mask_generation_algorithm.hash != *parameters.hash_algorithm_oid()
                || mask_generation_algorithm.mgf.to_id_string() != "1.2.840.113549.1.1.8"
            {
                return "0";
            }

            match (
                parameters.hash_algorithm_oid().to_id_string().as_str(),
                parameters.salt_length(),
            ) {
                ("2.16.840.1.101.3.4.2.1", 32) => "SHA256-RSAPSS",
                ("2.16.840.1.101.3.4.2.2", 48) => "SHA384-RSAPSS",
                ("2.16.840.1.101.3.4.2.3", 64) => "SHA512-RSAPSS",
                _ => "0",
            }
        }
        _ => "0",
    }
}

fn public_key_classification(public_key: &SubjectPublicKeyInfo<'_>) -> (String, Value) {
    let mut key_properties = json!({"primitive":"unknown"});
    let key_name = match public_key.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            let modulus = rsa
                .modulus
                .iter()
                .position(|byte| *byte != 0)
                .map_or(&[][..], |start| &rsa.modulus[start..]);
            let modulus_bits = modulus
                .first()
                .map_or(0, |byte| modulus.len() * 8 - byte.leading_zeros() as usize);
            key_properties["parameterSetIdentifier"] = modulus_bits.to_string().into();
            format!("RSA-{modulus_bits}")
        }
        Ok(PublicKey::EC(_)) => {
            let curve_oid = public_key
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.as_oid().ok())
                .map(|oid| oid.to_id_string());
            let curve = match curve_oid.as_deref() {
                Some("1.2.840.10045.3.1.7") => "P-256",
                Some("1.3.132.0.34") => "P-384",
                Some("1.3.132.0.35") => "P-521",
                Some("1.3.132.0.33") => "P-224",
                _ => "unknown",
            };
            key_properties = json!({"primitive":"signature","curve":curve});
            format!("ECDSA-{curve}")
        }
        _ if public_key.algorithm.algorithm.to_id_string() == "1.3.101.112" => {
            key_properties = json!({"primitive":"signature","curve":"Ed25519"});
            "Ed25519".into()
        }
        Ok(PublicKey::DSA(_)) => "DSA".into(),
        _ => "0".into(),
    };

    (key_name, key_properties)
}

pub(in crate::collectors::certificates) fn build(
    observations: &BTreeMap<String, Observation>,
    include_identity: bool,
    context: &CollectionContext,
) -> Result<Assets, CertificateError> {
    let mut components = BTreeMap::new();
    let mut algorithms = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for (digest, observation) in observations {
        context.check()?;
        let (_, certificate) =
            parse_x509_certificate(&observation.der).map_err(|_| CertificateError::Options)?;

        let (key_name, key_properties) = public_key_classification(certificate.public_key());
        let key_reference = algorithm(&mut algorithms, "public-key", &key_name, key_properties);
        let signature_reference = algorithm(
            &mut algorithms,
            "signature",
            signature_name(&certificate.signature_algorithm),
            json!({"primitive":"signature"}),
        );

        let mut certificate_properties = json!({"certificateFormat":"X.509","notValidBefore":certificate.validity().not_before.to_datetime().format(&Rfc3339).map_err(|_| CertificateError::Options)?,"notValidAfter":certificate.validity().not_after.to_datetime().format(&Rfc3339).map_err(|_| CertificateError::Options)?,"signatureAlgorithmRef":signature_reference});
        if include_identity {
            certificate_properties["subjectName"] = certificate.subject().to_string().into();
            certificate_properties["issuerName"] = certificate.issuer().to_string().into();
        }

        let reference = format!("certificate:sha256:{digest}");
        let mut properties = vec![
            json!({"name":"bommer:certificate:sha256","value":digest}),
            json!({"name":"bommer:certificate:public-key-algorithm-ref","value":key_reference}),
            json!({"name":"bommer:certificate:expired","value":(OffsetDateTime::now_utc().unix_timestamp() > certificate.validity().not_after.timestamp()).to_string()}),
            json!({"name":"bommer:certificate:trust-evaluated","value":"false"}),
        ];
        let source_paths: Vec<_> = observation
            .sources
            .iter()
            .map(|path| path_text(path))
            .collect();
        for path in &source_paths {
            properties.push(json!({"name":"bommer:certificate:source","value":path}));
        }
        sources.insert(reference.clone(), source_paths);
        components.insert(reference.clone(), json!({"type":"cryptographic-asset","bom-ref":reference,"name":format!("X.509 SHA-256 {digest}"),"cryptoProperties":{"assetType":"certificate","certificateProperties":certificate_properties},"properties":properties}));
    }

    components.extend(algorithms);

    Ok(Assets {
        document: Document::new(components.into_values().collect(), vec![], vec![]),
        evidence: json!({"sources":sources,"trust_evaluated":false}),
    })
}
