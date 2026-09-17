use base64::Engine;
use md5::{Digest, Md5};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Challenge {
    Basic {
        realm: Option<String>,
    },
    Digest {
        realm: String,
        nonce: String,
        opaque: Option<String>,
        algorithm: String,
        qop_auth: bool,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("不支持的 RTSP 鉴权方式")]
    Unsupported,
    #[error("Digest 鉴权参数缺少 realm 或 nonce")]
    MissingDigestParameter,
    #[error("Digest 仅支持 MD5、MD5-sess 和 qop=auth")]
    UnsupportedDigest,
}

pub fn parse_challenge(value: &str) -> Result<Challenge, AuthError> {
    let (scheme, parameters) = value.split_once(' ').unwrap_or((value, ""));
    let parameters = parse_parameters(parameters);
    if scheme.eq_ignore_ascii_case("basic") {
        return Ok(Challenge::Basic {
            realm: parameters.get("realm").cloned(),
        });
    }
    if !scheme.eq_ignore_ascii_case("digest") {
        return Err(AuthError::Unsupported);
    }
    let realm = parameters
        .get("realm")
        .cloned()
        .ok_or(AuthError::MissingDigestParameter)?;
    let nonce = parameters
        .get("nonce")
        .cloned()
        .ok_or(AuthError::MissingDigestParameter)?;
    let algorithm = parameters
        .get("algorithm")
        .cloned()
        .unwrap_or_else(|| "MD5".into());
    if !algorithm.eq_ignore_ascii_case("md5") && !algorithm.eq_ignore_ascii_case("md5-sess") {
        return Err(AuthError::UnsupportedDigest);
    }
    let qop_auth = parameters
        .get("qop")
        .is_some_and(|qop| qop.split(',').any(|part| part.trim() == "auth"));
    if parameters.contains_key("qop") && !qop_auth {
        return Err(AuthError::UnsupportedDigest);
    }
    Ok(Challenge::Digest {
        realm,
        nonce,
        opaque: parameters.get("opaque").cloned(),
        algorithm,
        qop_auth,
    })
}

pub fn authorization(
    challenge: &Challenge,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce_count: u32,
    cnonce: &str,
) -> String {
    match challenge {
        Challenge::Basic { .. } => {
            let value =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
            format!("Basic {value}")
        }
        Challenge::Digest {
            realm,
            nonce,
            opaque,
            algorithm,
            qop_auth,
        } => {
            let mut ha1 = md5_hex(&format!("{username}:{realm}:{password}"));
            if algorithm.eq_ignore_ascii_case("md5-sess") {
                ha1 = md5_hex(&format!("{ha1}:{nonce}:{cnonce}"));
            }
            let ha2 = md5_hex(&format!("{method}:{uri}"));
            let nc = format!("{nonce_count:08x}");
            let response = if *qop_auth {
                md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}"))
            } else {
                md5_hex(&format!("{ha1}:{nonce}:{ha2}"))
            };
            let mut value = format!(
                "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\", algorithm={algorithm}"
            );
            if *qop_auth {
                value.push_str(&format!(", qop=auth, nc={nc}, cnonce=\"{cnonce}\""));
            }
            if let Some(opaque) = opaque {
                value.push_str(&format!(", opaque=\"{opaque}\""));
            }
            value
        }
    }
}

fn parse_parameters(input: &str) -> BTreeMap<String, String> {
    let mut parameters = BTreeMap::new();
    let mut start = 0;
    let mut quoted = false;
    for (index, character) in input.char_indices() {
        match character {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                insert_parameter(&mut parameters, &input[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    insert_parameter(&mut parameters, &input[start..]);
    parameters
}

fn insert_parameter(parameters: &mut BTreeMap<String, String>, part: &str) {
    if let Some((key, value)) = part.trim().split_once('=') {
        parameters.insert(
            key.trim().to_ascii_lowercase(),
            value.trim().trim_matches('"').into(),
        );
    }
}

fn md5_hex(value: &str) -> String {
    format!("{:x}", Md5::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_rfc_digest_response_with_qop_auth() {
        let challenge = parse_challenge(
            "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
        )
        .unwrap();
        let header = authorization(
            &challenge,
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            1,
            "0a4f113b",
        );
        assert!(header.contains("response=\"6629fae49393a05397450978507c4ef1\""));
        assert!(header.contains("qop=auth"));
    }

    #[test]
    fn creates_basic_authorization() {
        let challenge = parse_challenge("Basic realm=\"camera\"").unwrap();
        assert_eq!(
            authorization(
                &challenge,
                "admin",
                "secret",
                "DESCRIBE",
                "rtsp://x/",
                1,
                "x"
            ),
            "Basic YWRtaW46c2VjcmV0"
        );
    }
}
