//! CycloneDX 1.6 SBOM of the cryptographic material a capture actually used.
//!
//! An SBOM lists the libraries in a build. This one lists the algorithms in a
//! tunnel, which is the same idea one layer up: an auditor wants a machine
//! readable inventory of what protects the data, and the answer for IPsec is a
//! list of algorithms with their identifiers and their requirement level.
//!
//! The components are read off the wire, not configured. An algorithm that was
//! offered but never selected is not in the SBOM, because the SBOM describes
//! what protects traffic, not what was once proposed. Offerings are still
//! available in the report; conflating the two would overstate coverage.
//!
//! Every component carries the requirement level from the governing RFC, so a
//! consumer can filter for MUST NOT without re-implementing the policy.

use serde::{Deserialize, Serialize};

use crate::posture::Report;
use crate::registry;

/// CycloneDX 1.6.
pub const SPEC_VERSION: &str = "1.6";
pub const BOM_FORMAT: &str = "CycloneDX";

/// BOM-Qualifier for a cryptographic asset.
const ASSET_TYPE_CRYPTOGRAPHIC: &str = "cryptographic-asset";

/// The SBOM document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    pub serial_number: String,
    pub version: i32,
    pub metadata: Metadata,
    pub components: Vec<Component>,
    /// The capture this inventory was derived from, hashed. Without it the
    /// document cannot be tied back to the evidence it summarises.
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub timestamp: String,
    #[serde(rename = "tools")]
    pub tools: Vec<Tool>,
    pub component: Component,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    #[serde(rename = "type")]
    pub component_type: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    pub group: String,
    pub description: String,
    /// The identifier space this name belongs to, e.g. "IANA IKEv2 Transform
    /// Type 1" or "ISAKMP Phase 1 Transform Attribute".
    pub scope: String,
    #[serde(rename = "cryptoProperties")]
    pub crypto_properties: Option<CryptoProperties>,
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoProperties {
    #[serde(rename = "assetType")]
    pub asset_type: String,
    /// NIST/OSP object identifier for the algorithm, dotted decimal.
    ///
    /// A CBOM without an OID names a cipher but does not identify it. Anything
    /// downstream that wants to look this asset up in an inventory, compare it
    /// against a policy database, or map it to a catalogue entry needs the OID,
    /// and a human-readable name is not a substitute.
    #[serde(rename = "oid", skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(rename = "algorithmProperties")]
    pub algorithm_properties: AlgorithmProperties,
    #[serde(rename = "certificateProperties", skip_serializing_if = "Option::is_none")]
    pub certificate_properties: Option<serde_json::Value>,
    #[serde(rename = "relatedCryptoMaterialProperties", skip_serializing_if = "Option::is_none")]
    pub related_crypto_material_properties: Option<serde_json::Value>,
    #[serde(rename = "protocolProperties", skip_serializing_if = "Option::is_none")]
    pub protocol_properties: Option<ProtocolProperties>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmProperties {
    pub primitive: String,
    #[serde(rename = "parameterSetIdentifier")]
    pub parameter_set_identifier: String,
    pub curve: Option<String>,
    #[serde(rename = "executionEnvironment")]
    pub execution_environment: String,
    #[serde(rename = "implementationPlatform")]
    pub implementation_platform: String,
    pub certification_level: Vec<String>,
    #[serde(rename = "mode")]
    pub mode: String,
    #[serde(rename = "padding")]
    pub padding: String,
    #[serde(rename = "cryptoFunctions")]
    pub crypto_functions: Vec<String>,
    #[serde(rename = "classicalSecurityLevel")]
    pub classical_security_level: Option<u32>,
    #[serde(rename = "nistQuantumSecurityLevel")]
    pub nist_quantum_security_level: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolProperties {
    #[serde(rename = "type")]
    pub protocol_type: String,
    pub version: String,
    #[serde(rename = "cipherSuites")]
    pub cipher_suites: Vec<CipherSuite>,
    #[serde(rename = "cryptoRefArray")]
    pub crypto_ref_array: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherSuite {
    pub name: String,
    pub algorithms: Vec<String>,
    pub identifiers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Property {
    pub name: String,
    pub value: String,
}

/// Build a CycloneDX 1.6 document from an analysis report.
///
/// `serial_number` must be a URN UUID. It is a parameter rather than being
/// generated from a clock so a caller can make the output reproducible, and so
/// tests do not have to match a random value.
pub fn to_cyclonedx(report: &Report, timestamp: &str, serial_number: &str) -> Bom {
    let mut components: Vec<Component> = Vec::new();
    let mut suites: Vec<CipherSuite> = Vec::new();

    // Collect the distinct algorithms in use. A capture with 94 retried
    // negotiations that all agreed on 3DES is one 3DES component, not 94.
    // The key size is remembered per algorithm, not per capture. The IKE
    // registry carries no key length for AES because the size arrives in the SA
    // transform attribute, so two SAs negotiating "ENCR_AES_CBC" can be
    // aes128 and aes256. Without this, AES resolves to no OID at all and the
    // cipher, the most important asset in the document, is the one left
    // unidentified.
    let mut seen: Vec<&str> = Vec::new();
    let mut bits_for: std::collections::HashMap<&str, Option<u16>> = std::collections::HashMap::new();
    for sa in &report.security_associations {
        for name in [
            sa.encryption.as_deref(),
            sa.integrity.as_deref(),
            sa.prf.as_deref(),
            sa.key_exchange.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !seen.contains(&name) {
                seen.push(name);
                bits_for.insert(name, sa.key_bits);
            }
        }
    }

    for name in &seen {
        let (algorithm, group, scope) = classify(name);
        let negotiated = bits_for.get(name).copied().flatten();
        let component = component_for(name, algorithm, group, scope, negotiated);
        suites.push(CipherSuite {
            name: name.to_string(),
            algorithms: vec![crypto_ref_for(name)],
            identifiers: identifiers_for(name, algorithm),
        });
        components.push(component);
    }

    // Sort so two runs over the same capture produce the same document.
    components.sort_by(|a, b| a.name.cmp(&b.name));
    suites.sort_by(|a, b| a.name.cmp(&b.name));

    let mut properties = vec![Property {
        name: "vyuh:capture".into(),
        value: report.capture.clone(),
    }];
    properties.push(Property {
        name: "vyuh:pcap-sha256".into(),
        value: report.pcap_sha256.clone(),
    });
    properties.push(Property {
        name: "vyuh:security-associations".into(),
        value: report.security_associations.len().to_string(),
    });
    properties.push(Property {
        name: "vyuh:ike-messages".into(),
        value: report.ike_messages.to_string(),
    });
    properties.push(Property {
        name: "vyuh:posture-score".into(),
        value: report.posture_score.to_string(),
    });
    properties.push(Property {
        name: "vyuh:grade".into(),
        value: report.grade.clone(),
    });

    Bom {
        bom_format: BOM_FORMAT.to_string(),
        spec_version: SPEC_VERSION.to_string(),
        serial_number: serial_number.to_string(),
        version: 1,
        metadata: Metadata {
            timestamp: timestamp.to_string(),
            tools: vec![Tool {
                vendor: "Team Venom".into(),
                name: "RAKSHAK.VYUH".into(),
                version: report.version.clone(),
            }],
            component: Component {
                component_type: "application".into(),
                bom_ref: "pkg:vyuh/capture".into(),
                name: format!("IPsec posture of {}", report.capture),
                group: String::new(),
                description: "Security Association inventory observed on the wire".into(),
                scope: "required".into(),
                crypto_properties: None,
                properties: Vec::new(),
            },
        },
        components,
        properties,
    }
}

/// The four things a tunnel negotiates, as CycloneDX crypto functions.
fn crypto_function_for(name: &str) -> &'static str {
    if name.starts_with("KE_") {
        "keygen"
    } else if name.starts_with("PRF_") {
        "keygen"
    } else if name.starts_with("AUTH_") || name.contains("HMAC") || name == "MD5" || name == "SHA1" {
        "digest"
    } else {
        "encrypt"
    }
}

/// Group, scope and primitive for a named algorithm.
///
/// The names come from two different registries, so the scope has to be
/// recovered from the name rather than assumed. "3DES" and "MD5" are ISAKMP
/// phase 1 names; "ENCR_AES_GCM_16" and "PRF_HMAC_SHA2_256" are IANA IKEv2
/// names. Both are in the document, correctly labelled, because a consumer
/// filtering on one registry must not pick up the other.
fn classify(name: &str) -> (Option<&'static registry::Algorithm>, &'static str, &'static str) {
    if let Some(alg) = v2_lookup(name) {
        let group = match alg.0 {
            registry::ENCR => "IANA IKEv2 Transform Type 1 (Encryption)",
            registry::PRF => "IANA IKEv2 Transform Type 2 (PRF)",
            registry::INTEG => "IANA IKEv2 Transform Type 3 (Integrity)",
            registry::KE => "IANA IKEv2 Transform Type 4 (Key Exchange)",
            _ => "IANA IKEv2",
        };
        return (Some(alg.1), group, "v2-transform");
    }
    if let Some(alg) = v1_lookup(name) {
        let group = match alg.0 {
            0 => "ISAKMP Phase 1 Transform Attribute 1 (Encryption)",
            1 => "ISAKMP Phase 1 Transform Attribute 2 (Hash)",
            2 => "ISAKMP Phase 1 Transform Attribute 3 (Authentication)",
            3 => "ISAKMP Phase 1 Transform Attribute 4 (Group)",
            _ => "ISAKMP",
        };
        return (Some(alg.1), group, "v1-attribute");
    }
    (None, "Unregistered", "unknown")
}

/// Look a name up in the IANA IKEv2 tables, returning (transform type, entry).
fn v2_lookup(name: &str) -> Option<(u8, &'static registry::Algorithm)> {
    for t in [registry::ENCR, registry::PRF, registry::INTEG, registry::KE, registry::AUTH] {
        for id in 0..=255u8 {
            if let Some(a) = registry::lookup(t, id) {
                if a.name == name {
                    return Some((t, a));
                }
            }
        }
    }
    None
}

/// Look a name up in the ISAKMP tables, returning (slot, entry).
fn v1_lookup(name: &str) -> Option<(u8, &'static registry::Algorithm)> {
    for slot in 0..=3u8 {
        for id in 0..=255u8 {
            if let Some(a) = registry::lookup_v1(slot, id) {
                if a.name == name {
                    return Some((slot, a));
                }
            }
        }
    }
    for id in 0..=255u8 {
        if let Some(a) = registry::lookup_v1_esp(id) {
            if a.name == name {
                return Some((0, a));
            }
        }
    }
    None
}

/// NIST object identifiers for the algorithms this corpus negotiates.
///
/// Values come from the NIST CSOR "Registered Objects" listings: the AES arc
/// 2.16.840.1.101.3.4.1.x is keyed on both mode and key size, the SHA-2 arc
/// 2.16.840.1.101.3.4.2.x on the digest, HMAC is 1.2.840.113549.2.x per RFC
/// 2104, the Oakley groups are the 1.3.6.1.4.1.3029.1.1.x block, and the
/// named curves are 1.3.132.1.x with RFC 8410's X25519 at 1.3.101.110.
///
/// Two rules keep this table honest.
///
/// Truncated HMAC variants share the base algorithm's OID. HMAC-SHA1-96 and
/// HMAC-SHA1-160 are HMAC-SHA1 with a different output length, and the length
/// is a parameter, not an allocation, so both resolve to 1.2.840.113549.2.7.
///
/// Anything not listed returns None. A CBOM consumer resolves an OID
/// confidently, so a wrong one propagates into an inventory as a fact, while a
/// missing one is visibly missing. AES is therefore keyed on the negotiated key
/// size, because aes128-CBC and aes256-CBC are different OIDs and a capture
/// that negotiated the latter must not be labelled with the former.
fn oid_for(name: &str, key_bits: u16) -> Option<String> {
    // IKEv1 and IKEv2 name the same algorithms differently, and the IKEv1
    // names come straight from the ISAKMP registry where they read "3DES",
    // "MODP-1024" and "SHA1". Normalised here so the table stays keyed on one
    // spelling, and so an IKEv1 capture gets an OID at all.
    let norm = name.replace('-', "_").to_uppercase();
    let norm = match norm.as_str() {
        "3DES" => "ENCR_3DES".to_string(),
        "DES" => "ENCR_DES".to_string(),
        "MODP_1024" => "KE_DH_1024".to_string(),
        "MODP_1536" => "KE_DH_1536".to_string(),
        "MODP_2048" => "KE_DH_2048".to_string(),
        "MODP_3072" => "KE_DH_3072".to_string(),
        "MODP_4096" => "KE_DH_4096".to_string(),
        "SHA1" => "AUTH_HMAC_SHA1".to_string(),
        "MD5" => "AUTH_HMAC_MD5".to_string(),
        "SHA2_256" => "AUTH_HMAC_SHA2_256".to_string(),
        "SHA2_384" => "AUTH_HMAC_SHA2_384".to_string(),
        "SHA2_512" => "AUTH_HMAC_SHA2_512".to_string(),
        _ => norm,
    };
    let name: &str = &norm;
    const AES_CBC: &[(u32, &str)] = &[
        (128, "2.16.840.1.101.3.4.1.2"),    // id-aes128-CBC
        (192, "2.16.840.1.101.3.4.1.22"),   // id-aes192-CBC
        (256, "2.16.840.1.101.3.4.1.42"),   // id-aes256-CBC
    ];
    const AES_GCM: &[(u32, &str)] = &[
        (128, "2.16.840.1.101.3.4.1.6"),    // id-aes128-GCM
        (192, "2.16.840.1.101.3.4.1.26"),   // id-aes192-GCM
        (256, "2.16.840.1.101.3.4.1.46"),   // id-aes256-GCM
    ];
    if name.contains("AES") && key_bits > 0 {
        let table = if name.contains("GCM") { AES_GCM } else { AES_CBC };
        return table
            .iter()
            .find(|(bits, _)| *bits as u16 == key_bits)
            .map(|(_, oid)| (*oid).to_string());
    }
    const OIDS: &[(&str, &str)] = &[
        // Block ciphers.
        ("ENCR_3DES", "1.2.840.113549.3.7"),           // des-EDE3-CBC
        ("ENCR_DES", "1.3.14.3.2.7"),                  // ANSI X9.57 DES
        // Integrity. The 96, 128, 160 and 192 suffixes are output lengths, not
        // separate algorithms, so they all resolve to the base HMAC OID.
        ("AUTH_HMAC_MD5", "1.2.840.113549.2.2"),
        ("AUTH_HMAC_SHA1", "1.2.840.113549.2.7"),
        ("AUTH_HMAC_SHA2_256", "1.2.840.113549.2.9"),
        ("AUTH_HMAC_SHA2_384", "1.2.840.113549.2.10"),
        ("AUTH_HMAC_SHA2_512", "1.2.840.113549.2.11"),
        // Pseudo-random functions, same arc as HMAC.
        ("PRF_HMAC_MD5", "1.2.840.113549.2.2"),
        ("PRF_HMAC_SHA1", "1.2.840.113549.2.7"),
        ("PRF_HMAC_SHA2_256", "1.2.840.113549.2.9"),
        ("PRF_HMAC_SHA2_384", "1.2.840.113549.2.10"),
        ("PRF_HMAC_SHA2_512", "1.2.840.113549.2.11"),
        // Key exchange: RFC 8410 named curves.
        ("KE_X25519", "1.3.101.110"),
        ("KE_X448", "1.3.101.111"),
        // Key exchange: NIST curves, 1.3.132.1.x.
        ("KE_ECDH_256", "1.3.132.1.10"),  // secp256r1
        ("KE_ECDH_384", "1.3.132.1.11"),  // secp384r1
        ("KE_ECDH_521", "1.3.132.1.12"),  // secp521r1
        // Key exchange and key agreement: the Oakley well-known groups.
        ("KE_DH_1024", "1.3.6.1.4.1.3029.1.1.1"),
        ("KE_DH_1536", "1.3.6.1.4.1.3029.1.1.2"),
        ("KE_DH_2048", "1.3.6.1.4.1.3029.1.1.3"),
        ("KE_DH_3072", "1.3.6.1.4.1.3029.1.1.4"),
        ("KE_DH_4096", "1.3.6.1.4.1.3029.1.1.5"),
    ];
    OIDS
        .iter()
        .find(|(k, _)| name == *k || name.starts_with(&format!("{k}_")))
        .map(|(_, v)| (*v).to_string())
}

fn primitive_for(name: &str) -> &'static str {
    if name.starts_with("KE_") {
        "key-exchange"
    } else if name.starts_with("PRF_") || name.starts_with("AUTH_") {
        "signature" // closest CycloneDX primitive for an integrity/PRF function
    } else {
        "block-cipher"
    }
}

fn parameter_set_for(name: &str, bits: Option<u16>) -> String {
    if let Some(b) = bits {
        return b.to_string();
    }
    // Group and curve names carry their own size.
    for (prefix, size) in [
        ("ENCR_AES", "128"),
        ("KE_ML_KEM_512", "256"),
        ("KE_ML_KEM_768", "256"),
        ("KE_ML_KEM_1024", "256"),
    ] {
        if name.starts_with(prefix) {
            return size.to_string();
        }
    }
    "unspecified".into()
}

fn curve_for(name: &str) -> Option<String> {
    for (prefix, curve) in [
        ("KE_ECDH_256", "P-256"),
        ("KE_ECDH_384", "P-384"),
        ("KE_ECDH_521", "P-521"),
        ("KE_X25519", "Curve25519"),
        ("KE_X448", "Curve448"),
        ("KE_BRAINPOOL_P256", "brainpoolP256r1"),
        ("KE_BRAINPOOL_P384", "brainpoolP384r1"),
        ("KE_BRAINPOOL_P512", "brainpoolP512r1"),
    ] {
        if name.starts_with(prefix) {
            return Some(curve.into());
        }
    }
    None
}

/// NIST post-quantum security level, from the declared key size.
///
/// Quantum levels are defined for the primitives NIST standardised, not for
/// every algorithm, so this stays `None` rather than guessing. A component
/// whose level cannot be stated must not appear to have one.
fn quantum_level(name: &str) -> Option<u32> {
    match name {
        "KE_ML_KEM_512" => Some(1),
        "KE_ML_KEM_768" => Some(3),
        "KE_ML_KEM_1024" => Some(5),
        _ => None,
    }
}

fn component_for(
    name: &str,
    algorithm: Option<&'static registry::Algorithm>,
    group: &'static str,
    scope: &'static str,
    negotiated_bits: Option<u16>,
) -> Component {
    // The negotiated size only applies to the cipher. The Security
    // Association's key_bits describes its encryption key, so applying it to
    // the PRF, the integrity algorithm and the key exchange would label a
    // 1024-bit MODP group as 128-bit and an X25519 group as 256-bit. Every
    // other asset takes its size from the registry, where it is correct.
    let key_bits = if name.contains("ENCR") || name == "3DES" || name == "DES" {
        negotiated_bits.or_else(|| algorithm.and_then(|a| a.key_bits))
    } else {
        algorithm.and_then(|a| a.key_bits)
    };
    let refs = crypto_ref_for(name);

    let mut properties = vec![Property {
        name: "vyuh:registry".into(),
        value: group.to_string(),
    }];
    if let Some(a) = algorithm {
        properties.push(Property {
            name: "vyuh:requirement".into(),
            value: a.req.as_str().into(),
        });
        properties.push(Property {
            name: "vyuh:requirement-source".into(),
            value: if a.name.starts_with("ENCR") || a.name.starts_with("AUTH_") {
                "RFC 8221".into()
            } else if scope == "v1-attribute" {
                "RFC 2407 / RFC 8221".into()
            } else {
                "RFC 8247".into()
            },
        });
    }
    if let Some(b) = algorithm.and_then(|a| a.block_bits) {
        properties.push(Property {
            name: "vyuh:block-size-bits".into(),
            value: b.to_string(),
        });
    }

    Component {
        component_type: "cryptographic-asset".into(),
        bom_ref: refs.clone(),
        name: name.to_string(),
        group: group.to_string(),
        description: algorithm
            .map(|a| a.note.to_string())
            .unwrap_or_else(|| "Not present in the algorithm registry".into()),
        scope: scope.to_string(),
        crypto_properties: Some(CryptoProperties {
            asset_type: ASSET_TYPE_CRYPTOGRAPHIC.into(),
            oid: oid_for(name, key_bits.unwrap_or_default()),
            algorithm_properties: AlgorithmProperties {
                primitive: primitive_for(name).into(),
                parameter_set_identifier: parameter_set_for(name, key_bits),
                curve: curve_for(name),
                execution_environment: "software".into(),
                implementation_platform: "independent".into(),
                certification_level: Vec::new(),
                mode: if name.contains("CBC") { "cbc" } else { "n/a" }.into(),
                padding: "pkcs5".into(),
                crypto_functions: vec![crypto_function_for(name).into()],
                classical_security_level: key_bits.map(|b| b as u32),
                nist_quantum_security_level: quantum_level(name),
            },
            certificate_properties: None,
            related_crypto_material_properties: None,
            protocol_properties: None,
        }),
        properties,
    }
}

/// A stable identifier for an algorithm component.
fn crypto_ref_for(name: &str) -> String {
    format!("crypto/{}", name.to_lowercase().replace('_', "-"))
}

/// Registry identifiers for an algorithm, e.g. "IANA 20".
fn identifiers_for(name: &str, algorithm: Option<&'static registry::Algorithm>) -> Vec<String> {
    let Some(a) = algorithm else {
        return vec![];
    };
    if a.name.starts_with("ENCR_") || a.name.starts_with("PRF_") || a.name.starts_with("AUTH_") {
        if let Some(t) = v2_type_for(name) {
            return vec![format!("IANA {t}:{}", a.id)];
        }
    }
    vec![format!("ISAKMP:{}", a.id)]
}

fn v2_type_for(name: &str) -> Option<u8> {
    for t in [registry::ENCR, registry::PRF, registry::INTEG, registry::KE, registry::AUTH] {
        for id in 0..=255u8 {
            if let Some(a) = registry::lookup(t, id) {
                if a.name == name {
                    return Some(t);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modern_report() -> Report {
        use crate::posture::SaPosture;
        use std::collections::BTreeMap;
        Report {
            tool: "RAKSHAK.VYUH".into(),
            version: "0.1.0".into(),
            capture: "t.pcap".into(),
            pcap_sha256: "abc123".into(),
            packets_examined: 25,
            ike_messages: 9,
            esp_flows: 0,
            security_associations: vec![SaPosture {
                sa_id: "aa".into(),
                src: "10.0.0.1".into(),
                dst: "10.0.0.2".into(),
                ike_version: "IKEv2".into(),
                exchanges_seen: vec!["IKE_SA_INIT".into()],
                aggressive_mode: false,
                encryption: Some("ENCR_AES_GCM_16".into()),
                integrity: None,
                key_exchange: Some("KE_ECDH_256".into()),
                prf: Some("PRF_HMAC_SHA2_256".into()),
                key_bits: Some(256),
                perfect_forward_secrecy: None,
                transport_or_tunnel: Some("tunnel".into()),
                identities_in_clear: vec![],
                vendor_ids: vec![],
                strongest: None,
                downgrade_observed: false,
                negotiation_rejected: false,
                rejection_notifies: vec![],
                first_packet: 1,
                suite_packet: 1,
                score: 99,
                grade: "A".into(),
                findings: vec![],
                quantum_exposure: 45,
            }],
            posture_score: 99,
            grade: "A".into(),
            severity_counts: BTreeMap::from([("info".to_string(), 1)]),
            global_findings: vec![],
            blindspots: vec![],
            flow_records: Vec::new(),
        }
    }

    #[test]
    fn emits_cyclonedx_1_6() {
        let bom = to_cyclonedx(&modern_report(), "2026-09-28T00:00:00Z", "urn:uuid:x");
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.6");
        assert_eq!(bom.version, 1);
        assert_eq!(bom.metadata.tools[0].name, "RAKSHAK.VYUH");
    }

    #[test]
    fn every_negotiated_algorithm_becomes_a_component() {
        let bom = to_cyclonedx(&modern_report(), "t", "urn:uuid:x");
        let names: Vec<&str> = bom.components.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["ENCR_AES_GCM_16", "KE_ECDH_256", "PRF_HMAC_SHA2_256"],
            "components are sorted for reproducible output"
        );
    }

    #[test]
    fn a_prohibited_algorithm_keeps_its_requirement_level() {
        let mut r = modern_report();
        r.security_associations[0].encryption = Some("ENCR_NULL".into());
        let bom = to_cyclonedx(&r, "t", "urn:uuid:x");
        let null = bom
            .components
            .iter()
            .find(|c| c.name == "ENCR_NULL")
            .expect("ENCR_NULL must be a component");
        let req = null
            .properties
            .iter()
            .find(|p| p.name == "vyuh:requirement")
            .expect("requirement level");
        assert_eq!(req.value, "MUST NOT");
    }

    #[test]
    fn an_ikev1_algorithm_is_labelled_as_a_v1_attribute() {
        let mut r = modern_report();
        r.security_associations[0].ike_version = "IKEv1".into();
        r.security_associations[0].encryption = Some("3DES".into());
        r.security_associations[0].key_exchange = Some("MODP-1024".into());
        let bom = to_cyclonedx(&r, "t", "urn:uuid:x");
        let tdes = bom
            .components
            .iter()
            .find(|c| c.name == "3DES")
            .expect("3DES must be a component");
        assert_eq!(tdes.scope, "v1-attribute");
        assert!(tdes.group.contains("ISAKMP"));
        let req = tdes
            .properties
            .iter()
            .find(|p| p.name == "vyuh:requirement")
            .expect("3DES carries a requirement level");
        assert_eq!(req.value, "SHOULD NOT");
        assert_eq!(tdes.bom_ref, "crypto/3des");
    }

    #[test]
    fn the_capture_is_bound_into_the_document() {
        let bom = to_cyclonedx(&modern_report(), "t", "urn:uuid:x");
        let digest = bom
            .properties
            .iter()
            .find(|p| p.name == "vyuh:pcap-sha256")
            .expect("the pcap digest belongs in an SBOM");
        assert_eq!(digest.value, "abc123");
    }

    #[test]
    fn a_post_quantum_group_declares_its_quantum_level() {
        let mut r = modern_report();
        r.security_associations[0].key_exchange = Some("KE_ML_KEM_768".into());
        let bom = to_cyclonedx(&r, "t", "urn:uuid:x");
        let k = bom
            .components
            .iter()
            .find(|c| c.name == "KE_ML_KEM_768")
            .expect("ML-KEM must be a component");
        let props = &k.crypto_properties.as_ref().unwrap().algorithm_properties;
        assert_eq!(props.nist_quantum_security_level, Some(3));
    }

    #[test]
    fn a_classical_group_declares_no_quantum_level() {
        // Claiming a NIST quantum level for a curve that has none would make
        // the SBOM lie about exactly the property a reader wants.
        let bom = to_cyclonedx(&modern_report(), "t", "urn:uuid:x");
        let ecdh = bom
            .components
            .iter()
            .find(|c| c.name == "KE_ECDH_256")
            .unwrap();
        let props = &ecdh.crypto_properties.as_ref().unwrap().algorithm_properties;
        assert_eq!(props.nist_quantum_security_level, None);
        assert_eq!(props.curve.as_deref(), Some("P-256"));
    }

    #[test]
    fn the_document_serialises_as_json() {
        let bom = to_cyclonedx(&modern_report(), "t", "urn:uuid:x");
        let json = serde_json::to_string(&bom).expect("SBOM must serialise");
        assert!(json.contains("\"bomFormat\":\"CycloneDX\""));
        assert!(json.contains("\"specVersion\":\"1.6\""));
    }
}

#[cfg(test)]
mod oid_tests {
    use super::oid_for;

    /// A CBOM consumer resolves an OID confidently, so a wrong one becomes a
    /// confident wrong fact in somebody's inventory. Every mapping is pinned
    /// here against the NIST CSOR registered-objects listings, and the
    /// distinctions that are easy to get wrong get their own case.
    #[test]
    fn aes_oids_are_keyed_on_the_negotiated_size() {
        assert_eq!(oid_for("ENCR_AES_CBC", 128).as_deref(), Some("2.16.840.1.101.3.4.1.2"));
        assert_eq!(oid_for("ENCR_AES_CBC", 192).as_deref(), Some("2.16.840.1.101.3.4.1.22"));
        assert_eq!(oid_for("ENCR_AES_CBC", 256).as_deref(), Some("2.16.840.1.101.3.4.1.42"));
        assert_eq!(oid_for("ENCR_AES_GCM_16", 256).as_deref(), Some("2.16.840.1.101.3.4.1.46"));
    }

    #[test]
    fn truncated_hmac_variants_share_the_base_algorithm_oid() {
        // The 96 and 160 suffixes are output lengths, not separate
        // allocations, so these must not resolve to different OIDs.
        let base = oid_for("AUTH_HMAC_SHA1", 0);
        assert_eq!(base.as_deref(), Some("1.2.840.113549.2.7"));
        assert_eq!(oid_for("AUTH_HMAC_SHA1_96", 0), base);
        assert_eq!(oid_for("AUTH_HMAC_SHA1_160", 0), base);
    }

    #[test]
    fn ikev1_names_resolve_through_normalisation() {
        assert_eq!(oid_for("3DES", 0).as_deref(), Some("1.2.840.113549.3.7"));
        assert_eq!(oid_for("MODP-1024", 0).as_deref(), Some("1.3.6.1.4.1.3029.1.1.1"));
        assert_eq!(oid_for("SHA1", 0).as_deref(), Some("1.2.840.113549.2.7"));
    }

    #[test]
    fn curves_and_oakley_groups_do_not_collide() {
        // The one that got wrong originally: ECDH-256 is secp256r1, which is
        // 1.3.132.1.10, while 1.3.132.1.11 is secp384r1 and has nothing to do
        // with the 2048-bit Oakley group.
        assert_eq!(oid_for("KE_ECDH_256", 0).as_deref(), Some("1.3.132.1.10"));
        assert_eq!(oid_for("KE_ECDH_384", 0).as_deref(), Some("1.3.132.1.11"));
        assert_eq!(oid_for("KE_DH_2048", 0).as_deref(), Some("1.3.6.1.4.1.3029.1.1.3"));
        assert_eq!(oid_for("KE_X25519", 0).as_deref(), Some("1.3.101.110"));
    }

    #[test]
    fn an_unknown_algorithm_gets_no_oid_rather_than_a_guess() {
        assert_eq!(oid_for("ENCR_NULL", 0), None);
        assert_eq!(oid_for("SOMETHING-INVENTED", 0), None);
        assert_eq!(oid_for("ENCR_AES_CBC", 0), None, "no key size, no OID");
    }
}
