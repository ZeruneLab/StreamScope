use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(BTreeMap<String, String>);

impl Headers {
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0
            .insert(name.into().trim().to_ascii_lowercase(), value.into());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(&name.to_ascii_lowercase()).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtspResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageError {
    #[error("RTSP 响应头不是 UTF-8")]
    Text,
    #[error("RTSP 状态行无效")]
    StatusLine,
    #[error("RTSP 状态码无效")]
    StatusCode,
    #[error("RTSP 响应头格式无效")]
    Header,
    #[error("Content-Length 无效")]
    ContentLength,
}

pub fn parse_response(input: &[u8]) -> Result<Option<(RtspResponse, usize)>, MessageError> {
    let Some(header_end) = input.windows(4).position(|part| part == b"\r\n\r\n") else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&input[..header_end]).map_err(|_| MessageError::Text)?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(MessageError::StatusLine)?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts
        .next()
        .filter(|value| value.starts_with("RTSP/"))
        .ok_or(MessageError::StatusLine)?;
    let status_code = status_parts
        .next()
        .ok_or(MessageError::StatusLine)?
        .parse()
        .map_err(|_| MessageError::StatusCode)?;
    let reason = status_parts.next().unwrap_or_default();
    let mut headers = Headers::default();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(MessageError::Header)?;
        headers.insert(name, value.trim());
    }
    let content_length = headers
        .get("content-length")
        .map(str::parse)
        .transpose()
        .map_err(|_| MessageError::ContentLength)?
        .unwrap_or(0);
    let body_start = header_end + 4;
    let consumed = body_start + content_length;
    if input.len() < consumed {
        return Ok(None);
    }
    Ok(Some((
        RtspResponse {
            version: version.into(),
            status_code,
            reason: reason.into(),
            headers,
            body: input[body_start..consumed].to_vec(),
        },
        consumed,
    )))
}

pub fn build_request(
    method: &str,
    uri: &str,
    cseq: u32,
    user_agent: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut request =
        format!("{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nUser-Agent: {user_agent}\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_for_complete_body_and_parses_case_insensitive_headers() {
        let partial = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 4\r\n\r\nab";
        assert!(parse_response(partial).unwrap().is_none());
        let mut complete = partial.to_vec();
        complete.extend_from_slice(b"cd");
        let (response, consumed) = parse_response(&complete).unwrap().unwrap();
        assert_eq!(consumed, complete.len());
        assert_eq!(response.headers.get("cseq"), Some("2"));
        assert_eq!(response.body, b"abcd");
    }
}
