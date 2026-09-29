use std::str;

const MAX_MESSAGE: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartLine {
    Request { method: String, uri: String },
    Response { status: u16, reason: String },
}

#[derive(Debug, Clone)]
pub struct SipMessage {
    pub start: StartLine,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl SipMessage {
    pub fn header(&self, name: &str) -> Option<&str> {
        let compact = match name.to_ascii_lowercase().as_str() {
            "call-id" => "i",
            "from" => "f",
            "to" => "t",
            "via" => "v",
            "content-length" => "l",
            "content-type" => "c",
            _ => "",
        };
        self.headers
            .iter()
            .find(|(key, _)| {
                key.eq_ignore_ascii_case(name)
                    || (!compact.is_empty() && key.eq_ignore_ascii_case(compact))
            })
            .map(|(_, value)| value.as_str())
    }

    pub fn method(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { method, .. } => Some(method),
            StartLine::Response { .. } => self
                .header("CSeq")
                .and_then(|value| value.split_whitespace().nth(1)),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SipError {
    #[error("SIP 头部不是有效 UTF-8")]
    HeaderEncoding,
    #[error("SIP 起始行无效")]
    StartLine,
    #[error("SIP 头字段无效")]
    Header,
    #[error("SIP Content-Length 无效或冲突")]
    ContentLength,
    #[error("SIP 消息超过 1 MiB 上限")]
    TooLarge,
    #[error("SIP 消息被截断")]
    Truncated,
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

pub fn message_length(bytes: &[u8]) -> Result<Option<usize>, SipError> {
    if bytes.len() > MAX_MESSAGE {
        return Err(SipError::TooLarge);
    }
    let Some(end) = header_end(bytes) else {
        return Ok(None);
    };
    let header = str::from_utf8(&bytes[..end]).map_err(|_| SipError::HeaderEncoding)?;
    let mut length = None;
    for line in header.split("\r\n").skip(1).filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':').ok_or(SipError::Header)?;
        if key.eq_ignore_ascii_case("content-length") || key.eq_ignore_ascii_case("l") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|_| SipError::ContentLength)?;
            if length.is_some_and(|old| old != parsed) {
                return Err(SipError::ContentLength);
            }
            length = Some(parsed);
        }
    }
    let total = end
        .checked_add(length.unwrap_or(0))
        .filter(|total| *total <= MAX_MESSAGE)
        .ok_or(SipError::TooLarge)?;
    Ok((bytes.len() >= total).then_some(total))
}

pub fn parse_message(bytes: &[u8]) -> Result<SipMessage, SipError> {
    let total = message_length(bytes)?.ok_or(SipError::Truncated)?;
    let end = header_end(bytes).ok_or(SipError::Truncated)?;
    let head = str::from_utf8(&bytes[..end]).map_err(|_| SipError::HeaderEncoding)?;
    let mut lines = head.split("\r\n");
    let first = lines.next().ok_or(SipError::StartLine)?;
    let start = if let Some(rest) = first.strip_prefix("SIP/2.0 ") {
        let (status, reason) = rest.split_once(' ').ok_or(SipError::StartLine)?;
        StartLine::Response {
            status: status.parse().map_err(|_| SipError::StartLine)?,
            reason: reason.to_string(),
        }
    } else {
        let mut parts = first.split_whitespace();
        let method = parts.next().ok_or(SipError::StartLine)?;
        let uri = parts.next().ok_or(SipError::StartLine)?;
        if parts.next() != Some("SIP/2.0") || parts.next().is_some() {
            return Err(SipError::StartLine);
        }
        StartLine::Request {
            method: method.to_string(),
            uri: uri.to_string(),
        }
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        if line.starts_with([' ', '\t']) {
            let Some((_, value)) = headers.last_mut() else {
                return Err(SipError::Header);
            };
            value.push(' ');
            value.push_str(line.trim());
            continue;
        }
        let (key, value) = line.split_once(':').ok_or(SipError::Header)?;
        if key.is_empty() {
            return Err(SipError::Header);
        }
        headers.push((key.to_string(), value.trim().to_string()));
    }
    Ok(SipMessage {
        start,
        headers,
        body: bytes[end..total].to_vec(),
    })
}

/// UDP preserves message boundaries, so a body without Content-Length occupies
/// the rest of the datagram. TCP framing must continue using `parse_message`.
pub fn parse_datagram(bytes: &[u8]) -> Result<SipMessage, SipError> {
    let mut message = parse_message(bytes)?;
    if message.header("Content-Length").is_none() {
        let end = header_end(bytes).ok_or(SipError::Truncated)?;
        message.body = bytes[end..].to_vec();
    }
    Ok(message)
}

pub fn is_sip_start(bytes: &[u8]) -> bool {
    if bytes.starts_with(b"SIP/2.0 ") {
        return true;
    }
    if [
        b"INVITE ".as_slice(),
        b"REGISTER ",
        b"OPTIONS ",
        b"ACK ",
        b"BYE ",
        b"CANCEL ",
        b"REFER ",
        b"UPDATE ",
        b"PRACK ",
        b"SUBSCRIBE ",
        b"NOTIFY ",
        b"MESSAGE ",
        b"INFO ",
    ]
    .iter()
    .any(|prefix| bytes.starts_with(prefix))
    {
        return true;
    }
    let Some(space) = bytes.iter().position(|byte| *byte == b' ') else {
        return false;
    };
    space > 0
        && space <= 16
        && bytes[..space].iter().all(|byte| byte.is_ascii_uppercase())
        && bytes.get(space + 1..).is_some_and(|rest| {
            rest.windows(8)
                .take(4096)
                .any(|window| window == b" SIP/2.0")
        })
}

pub fn parameter(value: &str, name: &str) -> Option<String> {
    value
        .split(';')
        .skip(1)
        .filter_map(|part| part.trim().split_once('='))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().trim_matches('"').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compact_headers_and_binary_body_by_byte_length() {
        let data =
            b"INVITE sip:b@host SIP/2.0\r\ni: abc\r\nf: <sip:a@host>;tag=1\r\nl: 2\r\n\r\n\xff\x00";
        let message = parse_message(data).unwrap();
        assert_eq!(message.header("Call-ID"), Some("abc"));
        assert_eq!(message.body, [255, 0]);
        assert_eq!(
            parameter(message.header("From").unwrap(), "tag"),
            Some("1".into())
        );
    }

    #[test]
    fn rejects_conflicting_lengths_and_partial_body() {
        assert_eq!(
            message_length(b"SIP/2.0 200 OK\r\nl: 1\r\nContent-Length: 2\r\n\r\nxx"),
            Err(SipError::ContentLength)
        );
        assert_eq!(
            parse_message(b"SIP/2.0 200 OK\r\nl: 2\r\n\r\nx").unwrap_err(),
            SipError::Truncated
        );
    }

    #[test]
    fn udp_uses_datagram_boundary_when_length_is_absent() {
        let data = b"INVITE sip:b@host SIP/2.0\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n";
        assert!(parse_message(data).unwrap().body.is_empty());
        assert_eq!(parse_datagram(data).unwrap().body, b"v=0\r\n");
    }
}
