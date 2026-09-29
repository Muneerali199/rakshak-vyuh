//! Algorithm registry: IANA identifiers mapped to names, key sizes, and the
//! requirement level each one carries in RFC 8221 (ESP/AH) and RFC 8247 (IKEv2).
//!
//! The requirement level is the point of this table. A finding is not "we think
//! this cipher is old" — it is "RFC 8221 marks ENCR_3DES as SHOULD NOT", which
//! is a citable statement a reviewer can check.

use serde::{Deserialize, Serialize};

/// RFC 2119-style strength of a requirement, as used by RFC 8221 / RFC 8247.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Req {
    Must,
    MustNot,
    Should,
    ShouldNot,
    May,
    Recommended, // RFC 8247 deprecates to "MUST-" semantics; we surface it as its own tier
    Deprecated,
}

impl Req {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Must => "MUST",
            Self::MustNot => "MUST NOT",
            Self::Should => "SHOULD",
            Self::ShouldNot => "SHOULD NOT",
            Self::May => "MAY",
            Self::Recommended => "MUST-",
            Self::Deprecated => "DEPRECATED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Algorithm {
    pub id: u8,
    pub name: &'static str,
    /// Effective key size in bits where meaningful.
    pub key_bits: Option<u16>,
    /// Block size in bits. 64-bit blocks are the SWEET32 birthday problem.
    pub block_bits: Option<u16>,
    pub req: Req,
    /// One line explaining the consequence, used verbatim in reports.
    pub note: &'static str,
}

impl Algorithm {
    /// Permitted by the relevant RFC. SHOULD NOT and MUST- are still legal, so
    /// they are usable, but they are reported separately.
    pub fn is_usable(&self) -> bool {
        !matches!(self.req, Req::MustNot | Req::Deprecated)
    }

    /// The RFC actively tells implementers not to do this.
    pub fn is_discouraged(&self) -> bool {
        matches!(self.req, Req::ShouldNot | Req::MustNot | Req::Deprecated)
    }

    /// Legal, but no longer recommended for new deployments.
    pub fn is_demoted(&self) -> bool {
        matches!(self.req, Req::Recommended)
    }
}

// -- IKEv2 Transform Type 1: encryption -----------------------------------

/// Transform identifiers come from the IANA "Transform Type 1 - Encryption
/// Algorithm Transform IDs" registry, not from RFC 3602 and not from a
/// guess at the ordering of the RFC's own figures. The two differ: RFC 3602
/// describes AES but allocates no IKEv2 number, and the legacy 1..9 block is
/// occupied by DES, 3DES, RC5, IDEA, CAST and BLOWFISH. Every id below was
/// read off the live registry; the capture regressions in `ike.rs` pin the
/// ones that real peers actually send.
pub const ENCR: u8 = 1;

pub static ENCR_ALGS: &[Algorithm] = &[
    Algorithm {
        id: 1,
        name: "ENCR_DES_IV64",
        key_bits: Some(64),
        block_bits: Some(64),
        req: Req::MustNot,
        note: "64-bit block DES. Broken and IANA-deprecated. RFC 8221 MUST NOT.",
    },
    Algorithm {
        id: 2,
        name: "ENCR_DES",
        key_bits: Some(56),
        block_bits: Some(64),
        req: Req::MustNot,
        note: "DES without an explicit IV. Broken and IANA-deprecated.",
    },
    Algorithm {
        id: 3,
        name: "ENCR_3DES",
        key_bits: Some(168),
        block_bits: Some(64),
        req: Req::ShouldNot,
        note: "64-bit block size: birthday collision after ~32 GB of ciphertext (SWEET32, CVE-2016-2183). RFC 8221 marks this SHOULD NOT.",
    },
    Algorithm {
        id: 5,
        name: "ENCR_IDEA",
        key_bits: Some(128),
        block_bits: Some(64),
        req: Req::MustNot,
        note: "64-bit block, so SWEET32 applies, and the cipher is patent-encumbered. IANA-deprecated; RFC 8247 does not list it.",
    },
    Algorithm {
        id: 8,
        name: "ENCR_3IDEA",
        key_bits: Some(128),
        block_bits: Some(64),
        req: Req::MustNot,
        note: "64-bit block. IANA-deprecated; no current guidance offers it.",
    },
    Algorithm {
        id: 11,
        name: "ENCR_NULL",
        key_bits: Some(0),
        block_bits: None,
        req: Req::MustNot,
        note: "No confidentiality whatsoever. RFC 8221 and RFC 8247 both mark ENCR_NULL MUST NOT. IANA lists the IKEv2 reference as 'not allowed'.",
    },
    Algorithm {
        id: 12,
        name: "ENCR_AES_CBC",
        key_bits: None, // carried in the SA transform attribute
        block_bits: Some(128),
        req: Req::Must,
        note: "AES-CBC; add a key-length transform attribute to pin the key size. The attribute is what distinguishes 128 from 256.",
    },
    Algorithm {
        id: 13,
        name: "ENCR_AES_CTR",
        key_bits: None,
        block_bits: Some(128),
        req: Req::May,
        note: "Counter mode gives no integrity on its own; only safe as part of an AEAD or with a separate INTEG transform.",
    },
    Algorithm {
        id: 14,
        name: "ENCR_AES_CCM_8",
        key_bits: None,
        block_bits: Some(128),
        req: Req::Should,
        note: "AEAD with an 8-byte tag. Acceptable where bandwidth, not tag strength, is the constraint.",
    },
    Algorithm {
        id: 16,
        name: "ENCR_AES_CCM_16",
        key_bits: None,
        block_bits: Some(128),
        req: Req::May,
        note: "AEAD with a 16-byte tag.",
    },
    Algorithm {
        id: 18,
        name: "ENCR_AES_GCM_8",
        key_bits: None,
        block_bits: Some(128),
        req: Req::ShouldNot,
        note: "AEAD with an 8-byte tag. GCM's tag is 128 bits; truncating to 64 is discouraged for the same reason as CCM_8.",
    },
    Algorithm {
        id: 19,
        name: "ENCR_AES_GCM_12",
        key_bits: None,
        block_bits: Some(128),
        req: Req::May,
        note: "AEAD with a 12-byte tag.",
    },
    Algorithm {
        id: 20,
        name: "ENCR_AES_GCM_16",
        key_bits: None,
        block_bits: Some(128),
        req: Req::Must,
        note: "AEAD with a 16-byte tag. RFC 8221 promotes this to MUST; the preferred modern choice. The key size comes from the key-length attribute, not the transform id.",
    },
    Algorithm {
        id: 23,
        name: "ENCR_CAMELLIA_CBC",
        key_bits: None,
        block_bits: Some(128),
        req: Req::May,
        note: "128-bit block, so no SWEET32 exposure. Mandated for use in Japan.",
    },
    Algorithm {
        id: 28,
        name: "ENCR_CHACHA20_POLY1305",
        key_bits: Some(256),
        block_bits: Some(128),
        req: Req::May,
        note: "Software-optimised AEAD. Strong choice on hardware without AES acceleration.",
    },
    Algorithm {
        id: 32,
        name: "ENCR_KUZNYECHIK_MGM_KTREE",
        key_bits: Some(256),
        block_bits: Some(128),
        req: Req::May,
        note: "Russian GOST block cipher in an AEAD mode. Interoperability is narrow outside the Russian national profile.",
    },
];

// -- IKEv2 Transform Type 2: pseudorandom function -------------------------

pub const PRF: u8 = 2;

/// IANA "Transform Type 2 - Pseudorandom Function Transform IDs". Note that
/// the SHA-2 PRFs are 5, 6 and 7: the 1..8 block is already occupied by MD5,
/// SHA-1, TIGER and AES-XCBC. Reading 3 as SHA-256 would label a peer that
/// sent TIGER as using the modern default.
pub static PRF_ALGS: &[Algorithm] = &[
    Algorithm {
        id: 1,
        name: "PRF_HMAC_MD5",
        key_bits: Some(128),
        block_bits: Some(128),
        req: Req::MustNot,
        note: "MD5 is fully broken. RFC 8247 marks PRF_HMAC_MD5 MUST NOT.",
    },
    Algorithm {
        id: 2,
        name: "PRF_HMAC_SHA1",
        key_bits: Some(160),
        block_bits: Some(160),
        req: Req::Recommended,
        note: "SHA-1 is no longer collision resistant. RFC 8247 demoted this to MUST-; migrate to PRF_HMAC_SHA2_256 or stronger.",
    },
    Algorithm {
        id: 3,
        name: "PRF_HMAC_TIGER",
        key_bits: Some(192),
        block_bits: Some(192),
        req: Req::MustNot,
        note: "IANA-deprecated. No current RFC offers it; treat any peer proposing it as non-compliant.",
    },
    Algorithm {
        id: 4,
        name: "PRF_AES128_XCBC",
        key_bits: Some(128),
        block_bits: Some(16),
        req: Req::May,
        note: "CMAC under an XCBC construction. Rare in practice.",
    },
    Algorithm {
        id: 5,
        name: "PRF_HMAC_SHA2_256",
        key_bits: Some(256),
        block_bits: Some(256),
        req: Req::Must,
        note: "The practical default PRF for new deployments. This is the id strongSwan sends for 'prfsha256'.",
    },
    Algorithm {
        id: 6,
        name: "PRF_HMAC_SHA2_384",
        key_bits: Some(384),
        block_bits: Some(384),
        req: Req::Must,
        note: "Strong SHA-2 PRF. Appropriate for longer-lived or higher-assurance SAs.",
    },
    Algorithm {
        id: 7,
        name: "PRF_HMAC_SHA2_512",
        key_bits: Some(512),
        block_bits: Some(512),
        req: Req::Must,
        note: "Strongest widely available SHA-2 PRF.",
    },
    Algorithm {
        id: 8,
        name: "PRF_AES128_CMAC",
        key_bits: Some(128),
        block_bits: Some(16),
        req: Req::May,
        note: "CMAC under a plain-AES construction. Rare in practice.",
    },
    Algorithm {
        id: 9,
        name: "PRF_HMAC_STREEBOG_512",
        key_bits: Some(512),
        block_bits: Some(512),
        req: Req::May,
        note: "Streebog (RFC 9385). Narrow interoperability outside its target profile.",
    },
];

// -- IKEv2 Transform Type 3: integrity -------------------------------------

pub const INTEG: u8 = 3;

/// IANA "Transform Type 3 - Integrity Algorithm Transform IDs". The truncated
/// HMAC-SHA-2 entries are 12, 13 and 14; 3 through 5 are DES-MAC, KPDK-MD5 and
/// AES-XCBC.
pub static INTEG_ALGS: &[Algorithm] = &[
    Algorithm {
        id: 1,
        name: "AUTH_HMAC_MD5_96",
        key_bits: Some(128),
        block_bits: Some(128),
        req: Req::MustNot,
        note: "MD5-based integrity. Broken hash; no assurance value.",
    },
    Algorithm {
        id: 2,
        name: "AUTH_HMAC_SHA1_96",
        key_bits: Some(160),
        block_bits: Some(160),
        req: Req::Recommended,
        note: "RFC 8221 demotes this from MUST to MUST-. Still widely deployed; flag and schedule a move to SHA-2.",
    },
    Algorithm {
        id: 3,
        name: "AUTH_DES_MAC",
        key_bits: Some(56),
        block_bits: Some(64),
        req: Req::MustNot,
        note: "64-bit block MAC, on top of a broken block cipher. RFC 8247 MUST NOT.",
    },
    Algorithm {
        id: 4,
        name: "AUTH_KPDK_MD5",
        key_bits: Some(128),
        block_bits: Some(128),
        req: Req::MustNot,
        note: "MD5-based. RFC 8247 marks this MUST NOT.",
    },
    Algorithm {
        id: 5,
        name: "AUTH_AES_XCBC_96",
        key_bits: Some(128),
        block_bits: Some(16),
        req: Req::May,
        note: "AES in XCBC mode. Effectively superseded by AES_CMAC_96.",
    },
    Algorithm {
        id: 6,
        name: "AUTH_HMAC_MD5_128",
        key_bits: Some(128),
        block_bits: Some(128),
        req: Req::MustNot,
        note: "MD5-based, wider tag. Still broken; the tag width adds nothing.",
    },
    Algorithm {
        id: 7,
        name: "AUTH_HMAC_SHA1_160",
        key_bits: Some(160),
        block_bits: Some(160),
        req: Req::Recommended,
        note: "SHA-1 with a full-width tag. Same SHA-1 objection as id 2; the wider tag does not fix collision resistance.",
    },
    Algorithm {
        id: 8,
        name: "AUTH_AES_CMAC_96",
        key_bits: Some(128),
        block_bits: Some(16),
        req: Req::May,
        note: "CMAC over AES. Efficient on hardware with AES-NI.",
    },
    Algorithm {
        id: 9,
        name: "AUTH_AES_128_GMAC",
        key_bits: Some(128),
        block_bits: Some(128),
        req: Req::May,
        note: "AES-GMAC integrity. Normally implied by an AEAD encryption transform rather than negotiated separately.",
    },
    Algorithm {
        id: 12,
        name: "AUTH_HMAC_SHA2_256_128",
        key_bits: Some(256),
        block_bits: Some(256),
        req: Req::Must,
        note: "Recommended integrity algorithm for new deployments.",
    },
    Algorithm {
        id: 13,
        name: "AUTH_HMAC_SHA2_384_192",
        key_bits: Some(384),
        block_bits: Some(384),
        req: Req::Must,
        note: "Strong integrity, appropriate for higher-assurance SAs.",
    },
    Algorithm {
        id: 14,
        name: "AUTH_HMAC_SHA2_512_256",
        key_bits: Some(512),
        block_bits: Some(512),
        req: Req::Must,
        note: "Strongest widely available SHA-2 integrity algorithm.",
    },
];

// -- IKEv2 Transform Type 4: key exchange ----------------------------------

pub const KE: u8 = 4;

/// IANA "Key Exchange Method Transform IDs" (formerly the Diffie-Hellman Group
/// registry). The MODP groups are not consecutive: 1536 is 5, then a gap, and
/// 2048 is 14. X25519 is 31 and Curve448 is 32. The post-quantum hybrids are
/// 35 to 37, not 38 to 40.
pub static KE_ALGS: &[Algorithm] = &[
    Algorithm {
        id: 1,
        name: "KE_DH_768",
        key_bits: Some(768),
        block_bits: None,
        req: Req::MustNot,
        note: "768-bit MODP. Within reach of commodity-resource discrete-log attacks; the Logjam paper measured 512-bit as breakable by nation-state actors.",
    },
    Algorithm {
        id: 2,
        name: "KE_DH_1024",
        key_bits: Some(1024),
        block_bits: None,
        req: Req::MustNot,
        note: "1024-bit MODP (Oakley Group 2). RFC 8247 marks this MUST NOT. 66% of scanned IPsec endpoints offered this group (Logjam, CCS 2015).",
    },
    Algorithm {
        id: 5,
        name: "KE_DH_1536",
        key_bits: Some(1536),
        block_bits: None,
        req: Req::May,
        note: "1536-bit MODP (Oakley Group 5). No known practical break, but below current guidance; prefer 2048 or an elliptic curve.",
    },
    Algorithm {
        id: 14,
        name: "KE_DH_2048",
        key_bits: Some(2048),
        block_bits: None,
        req: Req::Must,
        note: "2048-bit MODP (Oakley Group 14). RFC 8247 mandatory-to-implement; matches the NIST SP 800-77r1 recommendation.",
    },
    Algorithm {
        id: 15,
        name: "KE_DH_3072",
        key_bits: Some(3072),
        block_bits: None,
        req: Req::May,
        note: "3072-bit MODP (Oakley Group 15). Comfortably above current guidance at some CPU cost.",
    },
    Algorithm {
        id: 16,
        name: "KE_DH_4096",
        key_bits: Some(4096),
        block_bits: None,
        req: Req::May,
        note: "4096-bit MODP (Oakley Group 16). Matches the NSA CNSSP 15 minimum for classified material.",
    },
    Algorithm {
        id: 19,
        name: "KE_ECDH_256",
        key_bits: Some(256),
        block_bits: None,
        req: Req::Should,
        note: "NIST P-256. Elliptic-curve key exchange: equivalent strength to a 3072-bit MODP group at a fraction of the cost.",
    },
    Algorithm {
        id: 20,
        name: "KE_ECDH_384",
        key_bits: Some(384),
        block_bits: None,
        req: Req::May,
        note: "NIST P-384. Equivalent to a 384-bit classical security target.",
    },
    Algorithm {
        id: 21,
        name: "KE_ECDH_521",
        key_bits: Some(521),
        block_bits: None,
        req: Req::May,
        note: "NIST P-521. Highest-strength NIST curve, at the highest cost.",
    },
    Algorithm {
        id: 22,
        name: "KE_DH_1024_MODP160",
        key_bits: Some(1024),
        block_bits: None,
        req: Req::MustNot,
        note: "1024-bit MODP with a 160-bit prime-order subgroup. IANA-deprecated, and the subgroup gives no protection once the field is factored.",
    },
    Algorithm {
        id: 23,
        name: "KE_DH_2048_MODP224",
        key_bits: Some(2048),
        block_bits: None,
        req: Req::May,
        note: "2048-bit MODP with a 224-bit prime-order subgroup. Roughly 112-bit classical security.",
    },
    Algorithm {
        id: 24,
        name: "KE_DH_2048_MODP256",
        key_bits: Some(2048),
        block_bits: None,
        req: Req::Must,
        note: "2048-bit MODP with a 256-bit prime-order subgroup. The best of the RFC 5114 subgroup families; roughly 128-bit classical security.",
    },
    Algorithm {
        id: 28,
        name: "KE_BRAINPOOL_P256_R1",
        key_bits: Some(256),
        block_bits: None,
        req: Req::May,
        note: "brainpoolP256r1 (RFC 5639). European alternative to the NIST curves.",
    },
    Algorithm {
        id: 29,
        name: "KE_BRAINPOOL_P384_R1",
        key_bits: Some(384),
        block_bits: None,
        req: Req::May,
        note: "brainpoolP384r1 (RFC 5639).",
    },
    Algorithm {
        id: 30,
        name: "KE_BRAINPOOL_P512_R1",
        key_bits: Some(512),
        block_bits: None,
        req: Req::May,
        note: "brainpoolP512r1 (RFC 5639).",
    },
    Algorithm {
        id: 31,
        name: "KE_X25519",
        key_bits: Some(255),
        block_bits: None,
        req: Req::Should,
        note: "X25519 (RFC 7748, RFC 8031). Fast, constant-time, and the current default for new deployments.",
    },
    Algorithm {
        id: 32,
        name: "KE_X448",
        key_bits: Some(448),
        block_bits: None,
        req: Req::May,
        note: "X448 (RFC 7748). Higher margin than X25519 at slightly higher cost.",
    },
    Algorithm {
        id: 35,
        name: "KE_ML_KEM_512",
        key_bits: Some(256),
        block_bits: None,
        req: Req::May,
        note: "ML-KEM-512 (FIPS 203). Post-quantum, roughly 128-bit classical equivalent. Thin margin for long-horizon confidentiality.",
    },
    Algorithm {
        id: 36,
        name: "KE_ML_KEM_768",
        key_bits: Some(256),
        block_bits: None,
        req: Req::Recommended,
        note: "ML-KEM-768 (FIPS 203). The NIST level-3 post-quantum standard and the recommended hybrid partner for classical DH.",
    },
    Algorithm {
        id: 37,
        name: "KE_ML_KEM_1024",
        key_bits: Some(256),
        block_bits: None,
        req: Req::May,
        note: "ML-KEM-1024 (FIPS 203). Post-quantum, roughly 256-bit classical equivalent. Largest handshake payload of the three.",
    },
];

// -- IKEv2 Transform Type 14: authentication method -------------------------

pub const AUTH: u8 = 14;

pub static AUTH_ALGS: &[Algorithm] = &[
    Algorithm {
        id: 1,
        name: "AUTH_RSA",
        key_bits: Some(2048),
        block_bits: None,
        req: Req::May,
        note: "RSA signatures. Prefer certificates over pre-shared keys; RSA-2048 is the current floor.",
    },
    Algorithm {
        id: 3,
        name: "AUTH_ECDSA_P256",
        key_bits: Some(256),
        block_bits: None,
        req: Req::Should,
        note: "ECDSA over NIST P-256 with SHA-256. Strong default for certificate authentication.",
    },
    Algorithm {
        id: 4,
        name: "AUTH_ECDSA_P384",
        key_bits: Some(384),
        block_bits: None,
        req: Req::May,
        note: "ECDSA over NIST P-384 with SHA-384.",
    },
    Algorithm {
        id: 5,
        name: "AUTH_ECDSA_P521",
        key_bits: Some(521),
        block_bits: None,
        req: Req::May,
        note: "ECDSA over NIST P-521 with SHA-512.",
    },
    Algorithm {
        id: 7,
        name: "AUTH_RSASSA_PSS",
        key_bits: Some(2048),
        block_bits: None,
        req: Req::May,
        note: "RSASSA-PSS. The correct RSA signature scheme; PKCS#1 v1.5 is legacy.",
    },
    Algorithm {
        id: 9,
        name: "AUTH_PSK",
        key_bits: None,
        block_bits: None,
        req: Req::May,
        note: "Pre-shared key. In IKEv1 Aggressive Mode this is offline-crackable from a passive capture (CVE-2018-5389); prefer certificates for any long-lived tunnel.",
    },
    Algorithm {
        id: 10,
        name: "AUTH_EAP",
        key_bits: None,
        block_bits: None,
        req: Req::May,
        note: "EAP. Adds a round trip; appropriate for user authentication rather than gateway-to-gateway links.",
    },
];

/// Look up an algorithm by transform type and identifier.
pub fn lookup(transform_type: u8, id: u8) -> Option<&'static Algorithm> {
    let table: &'static [Algorithm] = match transform_type {
        ENCR => ENCR_ALGS,
        PRF => PRF_ALGS,
        INTEG => INTEG_ALGS,
        KE => KE_ALGS,
        AUTH => AUTH_ALGS,
        _ => return None,
    };
    table.iter().find(|a| a.id == id)
}

pub fn transform_type_name(t: u8) -> &'static str {
    match t {
        ENCR => "Encryption",
        PRF => "Pseudorandom Function",
        INTEG => "Integrity",
        KE => "Key Exchange",
        5 => "Extended Sequence Numbers",
        14 => "Authentication Method",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ids below are the ones a real peer puts on the wire. They were read
    /// off the live IANA registry and cross-checked against a strongSwan 5.9.13
    /// capture, not off an RFC's prose. Asserting them is what stops a future
    /// edit from quietly reintroducing a private numbering scheme.
    #[test]
    fn encr_ids_match_the_iana_registration() {
        assert_eq!(lookup(ENCR, 1).unwrap().name, "ENCR_DES_IV64");
        assert_eq!(lookup(ENCR, 2).unwrap().name, "ENCR_DES");
        assert_eq!(lookup(ENCR, 3).unwrap().name, "ENCR_3DES");
        assert_eq!(lookup(ENCR, 11).unwrap().name, "ENCR_NULL");
        assert_eq!(lookup(ENCR, 12).unwrap().name, "ENCR_AES_CBC");
        assert_eq!(lookup(ENCR, 20).unwrap().name, "ENCR_AES_GCM_16");
        assert_eq!(lookup(ENCR, 28).unwrap().name, "ENCR_CHACHA20_POLY1305");
    }

    #[test]
    fn prf_ids_match_the_iana_registration() {
        assert_eq!(lookup(PRF, 1).unwrap().name, "PRF_HMAC_MD5");
        assert_eq!(lookup(PRF, 2).unwrap().name, "PRF_HMAC_SHA1");
        assert_eq!(lookup(PRF, 3).unwrap().name, "PRF_HMAC_TIGER");
        assert_eq!(lookup(PRF, 5).unwrap().name, "PRF_HMAC_SHA2_256");
        assert_eq!(lookup(PRF, 7).unwrap().name, "PRF_HMAC_SHA2_512");
    }

    #[test]
    fn integrity_ids_match_the_iana_registration() {
        assert_eq!(lookup(INTEG, 2).unwrap().name, "AUTH_HMAC_SHA1_96");
        assert_eq!(lookup(INTEG, 3).unwrap().name, "AUTH_DES_MAC");
        assert_eq!(lookup(INTEG, 12).unwrap().name, "AUTH_HMAC_SHA2_256_128");
        assert_eq!(lookup(INTEG, 14).unwrap().name, "AUTH_HMAC_SHA2_512_256");
    }

    #[test]
    fn key_exchange_ids_match_the_iana_registration() {
        assert_eq!(lookup(KE, 2).unwrap().name, "KE_DH_1024");
        assert_eq!(lookup(KE, 14).unwrap().name, "KE_DH_2048");
        assert_eq!(lookup(KE, 19).unwrap().name, "KE_ECDH_256");
        assert_eq!(lookup(KE, 31).unwrap().name, "KE_X25519");
        assert_eq!(lookup(KE, 32).unwrap().name, "KE_X448");
        assert_eq!(lookup(KE, 36).unwrap().name, "KE_ML_KEM_768");
    }

    #[test]
    fn three_des_is_rated_should_not_by_rfc_8221() {
        let a = lookup(ENCR, 3).expect("3DES must be in the table");
        assert_eq!(a.name, "ENCR_3DES");
        assert_eq!(a.block_bits, Some(64));
        assert_eq!(a.req, Req::ShouldNot);
        assert!(a.is_discouraged(), "3DES is discouraged even though it is legal");
        assert!(a.is_usable(), "SHOULD NOT is a recommendation, not a prohibition");
        assert!(!a.is_demoted());
    }

    #[test]
    fn null_encryption_is_must_not() {
        assert_eq!(lookup(ENCR, 11).unwrap().req, Req::MustNot);
    }

    #[test]
    fn modp_1024_is_must_not_per_rfc_8247() {
        let a = lookup(KE, 2).unwrap();
        assert_eq!(a.name, "KE_DH_1024");
        assert_eq!(a.req, Req::MustNot);
    }

    #[test]
    fn modp_2048_and_x25519_are_acceptable() {
        assert!(lookup(KE, 14).unwrap().is_usable());
        assert!(lookup(KE, 31).unwrap().is_usable());
        assert!(lookup(KE, 19).unwrap().is_usable());
    }

    #[test]
    fn aes_gcm_is_the_preferred_modern_cipher() {
        let gcm = lookup(ENCR, 20).unwrap();
        assert_eq!(gcm.name, "ENCR_AES_GCM_16");
        assert_eq!(gcm.req, Req::Must);
        assert_eq!(gcm.block_bits, Some(128));
    }

    #[test]
    fn md5_prf_and_md5_integ_are_both_rejected() {
        assert_eq!(lookup(PRF, 1).unwrap().req, Req::MustNot);
        assert_eq!(lookup(INTEG, 1).unwrap().req, Req::MustNot);
    }

    #[test]
    fn sha1_is_demoted_not_banned() {
        let prf = lookup(PRF, 2).unwrap();
        let integ = lookup(INTEG, 2).unwrap();
        assert_eq!(prf.req, Req::Recommended);
        assert_eq!(integ.req, Req::Recommended);
        assert!(prf.is_demoted() && integ.is_demoted());
        assert!(prf.is_usable() && integ.is_usable());
        assert!(!prf.is_discouraged());
    }

    #[test]
    fn null_encryption_and_modp_1024_are_prohibited_not_merely_discouraged() {
        assert!(!lookup(ENCR, 11).unwrap().is_usable());
        assert!(!lookup(KE, 2).unwrap().is_usable());
        assert!(!lookup(PRF, 1).unwrap().is_usable());
    }

    #[test]
    fn ml_kem_768_is_registered_for_hybrid_ke() {
        assert_eq!(lookup(KE, 36).unwrap().name, "KE_ML_KEM_768");
    }

    #[test]
    fn unknown_transform_type_returns_none() {
        assert!(lookup(200, 1).is_none());
    }
}

// =========================================================================
// ISAKMP / IKEv1 transform identifiers
// =========================================================================
//
// IKEv1 and IKEv2 do not share a transform ID space. ISAKMP group 2 is
// MODP-1024 and so is IKEv2 transform 2, but ISAKMP group 5 is ECP-256 while
// IKEv2 transform 5 is AES-GCM-16. Resolving a v1 handshake against the v2
// tables would silently mislabel the suite, so the v1 tables are kept separate
// and the two are reconciled by name.

pub static V1_ENCR: &[Algorithm] = &[
    Algorithm { id: 1, name: "DES", key_bits: Some(56), block_bits: Some(64), req: Req::MustNot,
        note: "Single DES in CBC mode. Structurally obsolete; NIST withdrew FIPS 46-3." },
    Algorithm { id: 2, name: "IDEA", key_bits: Some(128), block_bits: Some(64), req: Req::MustNot,
        note: "IDEA in CBC mode. 64-bit block size and patent-encumbered. IANA-deprecated." },
    Algorithm { id: 3, name: "Blowfish", key_bits: Some(128), block_bits: Some(64), req: Req::MustNot,
        note: "Blowfish in CBC mode. 64-bit block size and a 8 to 56-bit key range." },
    Algorithm { id: 4, name: "RC5", key_bits: Some(128), block_bits: Some(64), req: Req::MustNot,
        note: "RC5. Variable block and key sizes, a 64-bit block, and an unmaintained cipher." },
    Algorithm { id: 5, name: "3DES", key_bits: Some(168), block_bits: Some(64), req: Req::ShouldNot,
        note: "Triple-DES in CBC mode, ISAKMP transform 5. 64-bit block size gives the SWEET32 birthday bound; RFC 8221 marks ENCR_3DES SHOULD NOT." },
    Algorithm { id: 6, name: "CAST5", key_bits: Some(128), block_bits: Some(64), req: Req::MustNot,
        note: "CAST5 in CBC mode. 64-bit block size. IANA-deprecated." },
    Algorithm { id: 7, name: "AES-CBC", key_bits: None, block_bits: Some(128), req: Req::Must,
        note: "AES in CBC mode, ISAKMP transform 7. Carry an explicit key length; the ID alone does not fix 128 versus 256." },
    Algorithm { id: 8, name: "Camellia-CBC", key_bits: Some(128), block_bits: Some(128), req: Req::May,
        note: "128-bit block size, so no SWEET32 exposure. Listed as MAY in RFC 8221." },
];

/// ESP/AH transform encryption identifiers (ISAKMP transform 3).
///
/// A Quick Mode or aggressive proposal for ESP puts the algorithm in the
/// transform id itself rather than in an attribute, and that numbering is
/// different again: 3DES is 3 here, not 5.
pub static V1_ESP_ENCR: &[Algorithm] = &[
    Algorithm { id: 1, name: "DES", key_bits: Some(64), block_bits: Some(64), req: Req::MustNot,
        note: "DES with an explicit 64-bit IV. Broken." },
    Algorithm { id: 2, name: "DES", key_bits: Some(56), block_bits: Some(64), req: Req::MustNot,
        note: "DES without an explicit IV. Broken." },
    Algorithm { id: 3, name: "3DES", key_bits: Some(168), block_bits: Some(64), req: Req::ShouldNot,
        note: "Triple-DES in CBC mode. 64-bit block size gives the SWEET32 birthday bound." },
    Algorithm { id: 4, name: "RC5", key_bits: Some(128), block_bits: Some(64), req: Req::MustNot,
        note: "RC5. 64-bit block, unmaintained cipher." },
    Algorithm { id: 5, name: "IDEA", key_bits: Some(128), block_bits: Some(64), req: Req::MustNot,
        note: "IDEA. 64-bit block and patent-encumbered. IANA-deprecated." },
    Algorithm { id: 6, name: "CAST", key_bits: Some(128), block_bits: Some(64), req: Req::MustNot,
        note: "CAST. 64-bit block. IANA-deprecated." },
    Algorithm { id: 7, name: "Blowfish", key_bits: Some(128), block_bits: Some(64), req: Req::MustNot,
        note: "Blowfish. 64-bit block and a variable key length." },
    Algorithm { id: 8, name: "3IDEA", key_bits: Some(168), block_bits: Some(64), req: Req::MustNot,
        note: "Triple IDEA. 64-bit block, IANA-deprecated." },
    Algorithm { id: 11, name: "ENCR_NULL", key_bits: Some(0), block_bits: None, req: Req::MustNot,
        note: "No confidentiality. RFC 8221 and RFC 8247 both mark ENCR_NULL MUST NOT." },
    Algorithm { id: 12, name: "AES-CBC", key_bits: None, block_bits: Some(128), req: Req::Must,
        note: "AES in CBC mode. Carry an explicit key length." },
    Algorithm { id: 13, name: "AES-CTR", key_bits: None, block_bits: Some(128), req: Req::May,
        note: "Counter mode supplies no integrity on its own." },
    Algorithm { id: 18, name: "ENCR_AES_GCM_8", key_bits: None, block_bits: Some(128), req: Req::ShouldNot,
        note: "GCM truncated to a 64-bit tag." },
    Algorithm { id: 19, name: "ENCR_AES_GCM_12", key_bits: None, block_bits: Some(128), req: Req::May,
        note: "GCM truncated to a 96-bit tag." },
    Algorithm { id: 20, name: "ENCR_AES_GCM_16", key_bits: None, block_bits: Some(128), req: Req::Must,
        note: "GCM with a full 128-bit tag. RFC 8221 promotes this to MUST." },
    Algorithm { id: 21, name: "SEED-CBC", key_bits: Some(128), block_bits: Some(128), req: Req::May,
        note: "SEED. 128-bit block. Not listed in RFC 8221." },
    Algorithm { id: 22, name: "Camellia-CBC", key_bits: Some(128), block_bits: Some(128), req: Req::May,
        note: "128-bit block size, so no SWEET32 exposure." },
];

pub static V1_HASH: &[Algorithm] = &[
    Algorithm { id: 1, name: "MD5", key_bits: Some(128), block_bits: Some(128), req: Req::MustNot,
        note: "Fully broken for collision resistance. An IKEv1 hash algorithm is used both for the PRF and for the HASH payload." },
    Algorithm { id: 2, name: "SHA1", key_bits: Some(160), block_bits: Some(160), req: Req::Recommended,
        note: "The default IKEv1 hash. IKEv1 cannot express SHA-2, which is a principal reason to migrate to IKEv2." },
    Algorithm { id: 3, name: "Tiger", key_bits: Some(192), block_bits: Some(192), req: Req::May,
        note: "Not listed in RFC 8221 and rarely deployed." },
    Algorithm { id: 4, name: "SHA-256", key_bits: Some(256), block_bits: Some(256), req: Req::Must,
        note: "Reachable only through IKEv1 interoperability extensions; prefer IKEv2." },
    Algorithm { id: 5, name: "SHA-384", key_bits: Some(384), block_bits: Some(384), req: Req::Must,
        note: "As SHA-256, via interop extension." },
    Algorithm { id: 6, name: "SHA-512", key_bits: Some(512), block_bits: Some(512), req: Req::Must,
        note: "As SHA-256, via interop extension." },
];

pub static V1_AUTH: &[Algorithm] = &[
    Algorithm { id: 1, name: "HMAC-MD5", key_bits: Some(128), block_bits: Some(128), req: Req::MustNot,
        note: "MD5-based authentication. No assurance value." },
    Algorithm { id: 2, name: "HMAC-SHA", key_bits: Some(160), block_bits: Some(160), req: Req::Recommended,
        note: "HMAC-SHA1 authentication, almost always with a pre-shared key. Combined with Aggressive Mode this is the configuration CVE-2018-5389 describes." },
    Algorithm { id: 3, name: "DSS", key_bits: Some(1024), block_bits: None, req: Req::May,
        note: "DSA signatures. 1024-bit DSA is below the current 2048-bit floor." },
    Algorithm { id: 4, name: "RSA-Encryption", key_bits: Some(2048), block_bits: None, req: Req::May,
        note: "RSA encryption without a signature. Provides no peer authentication against a substitution attack." },
    Algorithm { id: 5, name: "RSA-Signatures", key_bits: Some(2048), block_bits: None, req: Req::May,
        note: "PKCS#1 v1.5 signatures. RSASSA-PSS is the correct scheme where supported." },
    Algorithm { id: 6, name: "ElGamal", key_bits: None, block_bits: None, req: Req::May,
        note: "ElGamal signatures. Rarely deployed." },
    Algorithm { id: 7, name: "ECDSA", key_bits: Some(256), block_bits: None, req: Req::Should,
        note: "ECDSA signatures, normally over P-256." },
    Algorithm { id: 9, name: "HMAC-SHA-256", key_bits: Some(256), block_bits: Some(256), req: Req::Must,
        note: "Strong pre-shared-key authentication via interop extension." },
    Algorithm { id: 10, name: "HMAC-SHA-384", key_bits: Some(384), block_bits: Some(384), req: Req::Must,
        note: "Strong pre-shared-key authentication via interop extension." },
    Algorithm { id: 11, name: "HMAC-SHA-512", key_bits: Some(512), block_bits: Some(512), req: Req::Must,
        note: "Strong pre-shared-key authentication via interop extension." },
    Algorithm { id: 16, name: "XAUTH", key_bits: None, block_bits: None, req: Req::May,
        note: "Extended authentication, RFC 3947. Adds a round trip; typical for user rather than gateway authentication." },
];

pub static V1_GROUP: &[Algorithm] = &[
    Algorithm { id: 1, name: "MODP-768", key_bits: Some(768), block_bits: None, req: Req::MustNot,
        note: "768-bit MODP (Oakley Group 1). Within reach of commodity-resource discrete-log attacks." },
    Algorithm { id: 2, name: "MODP-1024", key_bits: Some(1024), block_bits: None, req: Req::MustNot,
        note: "1024-bit MODP (Oakley Group 2). The default IKEv1 group and the single most common IPsec weakness: 66% of scanned IPsec endpoints offered it (Logjam, CCS 2015)." },
    Algorithm { id: 3, name: "MODP-1536", key_bits: Some(1536), block_bits: None, req: Req::May,
        note: "1536-bit MODP (Oakley Group 5). No known practical break, but below current guidance." },
    Algorithm { id: 4, name: "MODP-2048", key_bits: Some(2048), block_bits: None, req: Req::Must,
        note: "2048-bit MODP (Oakley Group 14). The current IKEv1 minimum worth deploying." },
    Algorithm { id: 5, name: "ECP-256", key_bits: Some(256), block_bits: None, req: Req::Should,
        note: "NIST P-256. Note that IKEv1 group 5 is ECP-256, whereas IKEv2 transform 5 is ENCR_IDEA." },
    Algorithm { id: 6, name: "ECP-384", key_bits: Some(384), block_bits: None, req: Req::May,
        note: "NIST P-384." },
    Algorithm { id: 7, name: "ECP-521", key_bits: Some(521), block_bits: None, req: Req::May,
        note: "NIST P-521." },
];

/// Resolve an ISAKMP phase 1 transform. `slot` is the fixed order: 0
/// encryption, 1 hash, 2 authentication, 3 group.
pub fn lookup_v1(slot: u8, id: u8) -> Option<&'static Algorithm> {
    let table: &'static [Algorithm] = match slot {
        0 => V1_ENCR,
        1 => V1_HASH,
        2 => V1_AUTH,
        3 => V1_GROUP,
        _ => return None,
    };
    table.iter().find(|a| a.id == id)
}

/// Resolve an ISAKMP ESP/AH transform id, which uses the ESP numbering rather
/// than the phase 1 one. 3DES is 3 here and 5 in phase 1; resolving one with
/// the other table mislabels a 3DES tunnel as IDEA, or the reverse.
pub fn lookup_v1_esp(id: u8) -> Option<&'static Algorithm> {
    V1_ESP_ENCR.iter().find(|a| a.id == id)
}

#[cfg(test)]
mod v1_tests {
    use super::*;

    #[test]
    fn v1_and_v2_ids_are_different_number_spaces() {
        // ISAKMP group 2 is MODP-1024; IKEv2 transform 2 is single DES.
        assert_eq!(lookup_v1(3, 2).unwrap().name, "MODP-1024");
        assert_eq!(lookup(ENCR, 2).unwrap().name, "ENCR_DES");

        // ISAKMP group 5 is ECP-256; IKEv2 transform 5 is IDEA.
        assert_eq!(lookup_v1(3, 5).unwrap().name, "ECP-256");
        assert_eq!(lookup(ENCR, 5).unwrap().name, "ENCR_IDEA");
    }

    #[test]
    fn the_default_ikev1_suite_is_flagged_on_all_three_axes() {
        // ISAKMP phase 1 transform 5 is 3DES; the ESP numbering calls 3DES 3.
        // Reading either with the wrong table labels a 3DES tunnel IDEA.
        let encr = lookup_v1(0, 5).unwrap();
        assert_eq!(encr.name, "3DES");
        assert_eq!(encr.req, Req::ShouldNot);
        assert_eq!(encr.block_bits, Some(64));
        assert_eq!(lookup_v1(0, 2).unwrap().name, "IDEA");
        assert_eq!(lookup_v1_esp(3).unwrap().name, "3DES");
        assert_eq!(lookup_v1_esp(5).unwrap().name, "IDEA");
        assert_ne!(
            lookup_v1(0, 5).unwrap().name,
            lookup_v1_esp(5).unwrap().name,
            "the two ISAKMP numberings must not be interchangeable"
        );

        let hash = lookup_v1(1, 2).unwrap();
        assert_eq!(hash.name, "SHA1");
        assert_eq!(hash.req, Req::Recommended);

        let group = lookup_v1(3, 2).unwrap();
        assert_eq!(group.name, "MODP-1024");
        assert_eq!(group.req, Req::MustNot);
        assert!(!group.is_usable());
    }

    #[test]
    fn single_des_and_md5_are_prohibited() {
        assert!(!lookup_v1(0, 1).unwrap().is_usable());
        assert!(!lookup_v1(1, 1).unwrap().is_usable());
        assert!(!lookup_v1(2, 1).unwrap().is_usable());
    }

    #[test]
    fn modp_2048_and_ecp_256_are_acceptable_for_ikev1() {
        assert!(lookup_v1(3, 4).unwrap().is_usable());
        assert!(lookup_v1(3, 5).unwrap().is_usable());
        assert!(lookup_v1(0, 7).unwrap().is_usable());
    }

    #[test]
    fn an_out_of_range_slot_resolves_to_nothing() {
        assert!(lookup_v1(9, 1).is_none());
        assert!(lookup_v1(0, 200).is_none());
    }
}
