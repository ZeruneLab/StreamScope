//! Stateful test registrar. It deliberately does not own SDP or RTP processing.
use crate::{SipError, SipMessage, StartLine, build_response, parse_datagram};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(PartialEq, Eq)]
struct BusyKey {
    uri: String,
    via: String,
    from: String,
    to: String,
    call_id: String,
    cseq: String,
}

impl BusyKey {
    fn from_request(message: &SipMessage) -> Result<Self, SipError> {
        let StartLine::Request { uri, .. } = &message.start else {
            return Err(SipError::StartLine);
        };
        Ok(Self {
            uri: uri.clone(),
            via: message.header("Via").ok_or(SipError::Header)?.into(),
            from: message.header("From").ok_or(SipError::Header)?.into(),
            to: message.header("To").ok_or(SipError::Header)?.into(),
            call_id: message.header("Call-ID").ok_or(SipError::Header)?.into(),
            cseq: message
                .header("CSeq")
                .and_then(|value| value.split_whitespace().next())
                .ok_or(SipError::Header)?
                .into(),
        })
    }
}

struct BusyTransaction {
    key: BusyKey,
    response: Vec<u8>,
    to_tag: String,
    acknowledged: bool,
    expires_at: Instant,
}

/// Deterministic negative INVITE scenario; it never accepts or creates media.
#[derive(Default)]
pub struct SipBusy {
    transactions: Vec<BusyTransaction>,
}

impl SipBusy {
    pub fn respond(&mut self, data: &[u8]) -> Result<Option<(Vec<u8>, u16)>, SipError> {
        let message = parse_datagram(data)?;
        let Some(method) = message.method() else {
            return Ok(None);
        };
        if !matches!(method, "INVITE" | "CANCEL" | "ACK") {
            return Ok(None);
        }
        let now = Instant::now();
        self.transactions.retain(|item| item.expires_at > now);
        let mut key = BusyKey::from_request(&message)?;
        let ack_tag = if method == "ACK" {
            let tag = crate::message::parameter(&key.to, "tag");
            key.to = key.to.split(';').next().unwrap_or_default().to_string();
            tag
        } else {
            None
        };
        let matched = self.transactions.iter().find(|item| item.key == key);
        match method {
            "INVITE" => {
                if let Some(item) = matched {
                    return Ok((!item.acknowledged).then(|| (item.response.clone(), 486)));
                }
                let response = build_response(&message, 486, "Busy Here", "OPTIONS, INVITE", &[])?;
                let to_tag = parse_datagram(&response)?
                    .header("To")
                    .and_then(|value| crate::message::parameter(value, "tag"))
                    .ok_or(SipError::Header)?;
                if self.transactions.len() >= 1024 {
                    self.transactions.remove(0);
                }
                self.transactions.push(BusyTransaction {
                    key,
                    response: response.clone(),
                    to_tag,
                    acknowledged: false,
                    expires_at: now + Duration::from_secs(32),
                });
                Ok(Some((response, 486)))
            }
            "CANCEL" => {
                let (status, reason) = if matched.is_some() {
                    (200, "OK")
                } else {
                    (481, "Call/Transaction Does Not Exist")
                };
                let mut reply_to = message.clone();
                if let Some(item) = matched
                    && let Some((_, value)) = reply_to.headers.iter_mut().find(|(name, _)| {
                        name.eq_ignore_ascii_case("To") || name.eq_ignore_ascii_case("t")
                    })
                {
                    *value = format!("{};tag={}", item.key.to, item.to_tag);
                }
                let response = build_response(&reply_to, status, reason, "OPTIONS, INVITE", &[])?;
                Ok(Some((response, status)))
            }
            "ACK" => {
                if let Some(item) = self.transactions.iter_mut().find(|item| item.key == key)
                    && ack_tag.as_deref() == Some(item.to_tag.as_str())
                {
                    item.acknowledged = true;
                    item.expires_at = now + Duration::from_secs(5);
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DigestAlgorithm {
    Sha256,
    Md5,
}

impl DigestAlgorithm {
    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Md5 => "MD5",
        }
    }

    fn hash(self, input: &str) -> String {
        match self {
            Self::Sha256 => format!("{:x}", Sha256::digest(input.as_bytes())),
            Self::Md5 => format!("{:x}", Md5::digest(input.as_bytes())),
        }
    }
}

struct Binding {
    contact: String,
    expires_at: Instant,
}

pub struct SipRegistrar {
    username: String,
    password: String,
    realm: String,
    nonce: String,
    algorithm: DigestAlgorithm,
    bindings: HashMap<String, Binding>,
    nonce_counts: HashMap<String, u32>,
    response_cache: HashMap<[u8; 20], (Vec<u8>, Instant)>,
}

impl SipRegistrar {
    pub fn new(username: String, password: String, algorithm: DigestAlgorithm) -> Self {
        Self {
            username,
            password,
            realm: "StreamScope Test".into(),
            nonce: Uuid::new_v4().simple().to_string(),
            algorithm,
            bindings: HashMap::new(),
            nonce_counts: HashMap::new(),
            response_cache: HashMap::new(),
        }
    }

    pub fn respond(&mut self, data: &[u8]) -> Result<Option<(Vec<u8>, u16)>, SipError> {
        let message = parse_datagram(data)?;
        if message.method() != Some("REGISTER") {
            return Ok(None);
        }
        let now = Instant::now();
        self.bindings.retain(|_, binding| binding.expires_at > now);
        self.response_cache
            .retain(|_, (_, when)| now.duration_since(*when) < Duration::from_secs(32));
        let fingerprint: [u8; 20] = Sha1::digest(data).into();
        if let Some((cached, _)) = self.response_cache.get(&fingerprint) {
            return Ok(Some((cached.clone(), 200)));
        }
        if !self.authenticated(&message) {
            let challenge = format!(
                "Digest realm=\"{}\", nonce=\"{}\", algorithm={}, qop=\"auth\"",
                self.realm,
                self.nonce,
                self.algorithm.name()
            );
            return build_response(
                &message,
                401,
                "Unauthorized",
                "OPTIONS, REGISTER",
                &[("WWW-Authenticate", &challenge)],
            )
            .map(|response| Some((response, 401)));
        }
        let Some(aor) = message.header("To") else {
            return Err(SipError::Header);
        };
        let expires = match message.header("Expires") {
            Some(value) => match value.parse::<u32>() {
                Ok(value) => value.min(3600),
                Err(_) => {
                    return build_response(&message, 400, "Bad Request", "OPTIONS, REGISTER", &[])
                        .map(|response| Some((response, 400)));
                }
            },
            None => 3600,
        };
        if let Some(contact) = message.header("Contact") {
            if contact == "*" && expires == 0 {
                self.bindings.remove(aor);
            } else if contact == "*" || contact.contains(',') || contact.is_empty() {
                return build_response(&message, 400, "Bad Request", "OPTIONS, REGISTER", &[])
                    .map(|response| Some((response, 400)));
            } else {
                let contact_expires = crate::message::parameter(contact, "expires")
                    .and_then(|value| value.parse::<u32>().ok())
                    .unwrap_or(expires)
                    .min(3600);
                if contact_expires == 0 {
                    self.bindings.remove(aor);
                } else {
                    self.bindings.insert(
                        aor.to_string(),
                        Binding {
                            contact: contact.to_string(),
                            expires_at: now + Duration::from_secs(contact_expires as u64),
                        },
                    );
                }
            }
        }
        let (contact, remaining) = self
            .bindings
            .get(aor)
            .map(|binding| {
                (
                    binding.contact.clone(),
                    binding
                        .expires_at
                        .saturating_duration_since(now)
                        .as_secs()
                        .to_string(),
                )
            })
            .unwrap_or_default();
        let mut extra = Vec::new();
        if !contact.is_empty() {
            extra.push(("Contact", contact.as_str()));
            extra.push(("Expires", remaining.as_str()));
        }
        let response = build_response(&message, 200, "OK", "OPTIONS, REGISTER", &extra)?;
        if self.response_cache.len() >= 1024 {
            self.response_cache.clear();
        }
        self.response_cache
            .insert(fingerprint, (response.clone(), now));
        Ok(Some((response, 200)))
    }

    fn authenticated(&mut self, message: &SipMessage) -> bool {
        let Some(header) = message.header("Authorization") else {
            return false;
        };
        let Some(params) = digest_parameters(header) else {
            return false;
        };
        let get = |name: &str| params.get(name).map(String::as_str).unwrap_or("");
        let StartLine::Request { method, uri } = &message.start else {
            return false;
        };
        if get("username") != self.username
            || get("realm") != self.realm
            || get("nonce") != self.nonce
            || get("uri") != uri
            || !get("algorithm").eq_ignore_ascii_case(self.algorithm.name())
            || !get("qop").eq_ignore_ascii_case("auth")
            || get("cnonce").is_empty()
            || get("nc").len() != 8
        {
            return false;
        }
        let Ok(nonce_count) = u32::from_str_radix(get("nc"), 16) else {
            return false;
        };
        if nonce_count == 0 {
            return false;
        }
        let replay_key = format!("{}:{}", self.username, get("cnonce"));
        if self
            .nonce_counts
            .get(&replay_key)
            .is_some_and(|previous| nonce_count <= *previous)
        {
            return false;
        }
        let ha1 = self.algorithm.hash(&format!(
            "{}:{}:{}",
            self.username, self.realm, self.password
        ));
        let ha2 = self.algorithm.hash(&format!("{method}:{uri}"));
        let expected = self.algorithm.hash(&format!(
            "{ha1}:{}:{}:{}:auth:{ha2}",
            self.nonce,
            get("nc"),
            get("cnonce")
        ));
        if !constant_time_equal(
            expected.as_bytes(),
            get("response").to_ascii_lowercase().as_bytes(),
        ) {
            return false;
        }
        self.nonce_counts.insert(replay_key, nonce_count);
        true
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn digest_parameters(header: &str) -> Option<HashMap<String, String>> {
    let mut input = header.strip_prefix("Digest ")?.trim();
    let mut fields = HashMap::new();
    while !input.is_empty() {
        let (name, rest) = input.split_once('=')?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return None;
        }
        let rest = rest.trim_start();
        let (value, remaining) = if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"')?;
            (quoted[..end].to_string(), &quoted[end + 1..])
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            (rest[..end].trim().to_string(), &rest[end..])
        };
        fields.insert(name, value);
        input = remaining.trim_start().trim_start_matches(',').trim_start();
    }
    Some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn busy_request(method: &str, branch: &str, to: &str) -> Vec<u8> {
        format!(
            "{method} sip:b@example.test SIP/2.0\r\nVia: SIP/2.0/UDP client;branch={branch}\r\nFrom: <sip:a@example.test>;tag=from-a\r\nTo: {to}\r\nCall-ID: busy-call\r\nCSeq: 7 {method}\r\nContent-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn busy_scenario_matches_cancel_ack_and_retransmissions() {
        let mut busy = SipBusy::default();
        let invite = busy_request("INVITE", "z9hG4bK-1", "<sip:b@example.test>");
        let (declined, status) = busy.respond(&invite).unwrap().unwrap();
        assert_eq!(status, 486);
        assert_eq!(busy.respond(&invite).unwrap().unwrap().0, declined);
        let tag = crate::message::parameter(
            parse_datagram(&declined).unwrap().header("To").unwrap(),
            "tag",
        )
        .unwrap();
        let wrong_cancel = busy_request("CANCEL", "z9hG4bK-other", "<sip:b@example.test>");
        assert_eq!(busy.respond(&wrong_cancel).unwrap().unwrap().1, 481);
        let cancel = busy_request("CANCEL", "z9hG4bK-1", "<sip:b@example.test>");
        let (cancel_response, status) = busy.respond(&cancel).unwrap().unwrap();
        assert_eq!(status, 200);
        assert_eq!(
            crate::message::parameter(
                parse_datagram(&cancel_response)
                    .unwrap()
                    .header("To")
                    .unwrap(),
                "tag"
            ),
            Some(tag.clone())
        );
        let wrong_ack = busy_request("ACK", "z9hG4bK-1", "<sip:b@example.test>;tag=wrong");
        assert!(busy.respond(&wrong_ack).unwrap().is_none());
        assert_eq!(busy.respond(&invite).unwrap().unwrap().0, declined);
        let ack = busy_request(
            "ACK",
            "z9hG4bK-1",
            &format!("<sip:b@example.test>;tag={tag}"),
        );
        assert!(busy.respond(&ack).unwrap().is_none());
        assert!(busy.respond(&invite).unwrap().is_none());
        assert_eq!(busy.respond(&cancel).unwrap().unwrap().1, 200);
    }

    fn register(auth: &str, expires: u32) -> Vec<u8> {
        format!("REGISTER sip:example.test SIP/2.0\r\nVia: SIP/2.0/UDP client;branch=z9hG4bK-1\r\nFrom: <sip:alice@example.test>;tag=a\r\nTo: <sip:alice@example.test>\r\nCall-ID: test-call\r\nCSeq: 1 REGISTER\r\nContact: <sip:alice@10.0.0.1>\r\nExpires: {expires}\r\n{auth}Content-Length: 0\r\n\r\n").into_bytes()
    }

    #[test]
    fn digest_registration_requires_auth_and_tracks_binding() {
        let mut registrar =
            SipRegistrar::new("alice".into(), "secret".into(), DigestAlgorithm::Sha256);
        let unauthenticated = register("", 60);
        let (challenge, status) = registrar.respond(&unauthenticated).unwrap().unwrap();
        assert_eq!(status, 401);
        let parsed = parse_datagram(&challenge).unwrap();
        assert!(
            parsed
                .header("WWW-Authenticate")
                .unwrap()
                .contains("algorithm=SHA-256")
        );
        let ha1 = DigestAlgorithm::Sha256.hash("alice:StreamScope Test:secret");
        let ha2 = DigestAlgorithm::Sha256.hash("REGISTER:sip:example.test");
        let response = DigestAlgorithm::Sha256.hash(&format!(
            "{ha1}:{}:00000001:client-nonce:auth:{ha2}",
            registrar.nonce
        ));
        let authorization = format!(
            "Authorization: Digest username=\"alice\",realm=\"StreamScope Test\",nonce=\"{}\",uri=\"sip:example.test\",algorithm=SHA-256,qop=auth,nc=00000001,cnonce=\"client-nonce\",response=\"{response}\"\r\n",
            registrar.nonce
        );
        let request = register(&authorization, 60);
        let (accepted, status) = registrar.respond(&request).unwrap().unwrap();
        assert_eq!(status, 200);
        assert!(String::from_utf8_lossy(&accepted).contains("Contact: <sip:alice@10.0.0.1>"));
        assert_eq!(
            registrar.respond(&request).unwrap().unwrap().0,
            accepted,
            "UDP 重传应复用原应答"
        );
        let changed = register(&authorization, 0);
        assert_eq!(
            registrar.respond(&changed).unwrap().unwrap().1,
            401,
            "重复 nonce-count 不能用于新请求"
        );
    }
}
