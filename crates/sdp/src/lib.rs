use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::Url;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SdpSession {
    pub session_name: Option<String>,
    pub control: Option<String>,
    pub range: Option<String>,
    pub attributes: BTreeMap<String, Vec<String>>,
    pub media: Vec<SdpMedia>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SdpMedia {
    pub media_type: String,
    pub port: u16,
    pub protocol: String,
    pub payload_types: Vec<u8>,
    pub control: Option<String>,
    pub range: Option<String>,
    pub frame_rate: Option<String>,
    pub frame_size: Option<String>,
    pub rtp_maps: BTreeMap<u8, RtpMap>,
    pub fmtp: BTreeMap<u8, BTreeMap<String, String>>,
    pub attributes: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RtpMap {
    pub encoding: String,
    pub clock_rate: u32,
    pub channels: Option<u16>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SdpError {
    #[error("SDP 第 {line} 行缺少 '=' 分隔符")]
    MissingSeparator { line: usize },
    #[error("SDP 第 {line} 行的媒体描述无效")]
    InvalidMedia { line: usize },
    #[error("SDP 第 {line} 行的 rtpmap 无效")]
    InvalidRtpMap { line: usize },
    #[error("SDP 缺少必需的 v= 行")]
    MissingVersion,
    #[error("Control URI 无法解析")]
    InvalidControlUri,
}

pub fn parse_sdp(input: &str) -> Result<SdpSession, SdpError> {
    let mut session = SdpSession::default();
    let mut current_media: Option<usize> = None;
    let mut saw_version = false;
    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        let (kind, value) = line
            .split_once('=')
            .ok_or(SdpError::MissingSeparator { line: line_number })?;
        if kind.len() != 1 {
            return Err(SdpError::MissingSeparator { line: line_number });
        }
        match kind {
            "v" => saw_version = true,
            "s" if current_media.is_none() => session.session_name = Some(value.into()),
            "m" => {
                session.media.push(parse_media(value, line_number)?);
                current_media = Some(session.media.len() - 1);
            }
            "a" => {
                let (name, attribute_value) = value.split_once(':').unwrap_or((value, ""));
                if let Some(media_index) = current_media {
                    apply_media_attribute(
                        &mut session.media[media_index],
                        name,
                        attribute_value,
                        line_number,
                    )?;
                } else {
                    match name {
                        "control" => session.control = Some(attribute_value.into()),
                        "range" => session.range = Some(attribute_value.into()),
                        _ => session
                            .attributes
                            .entry(name.into())
                            .or_default()
                            .push(attribute_value.into()),
                    }
                }
            }
            _ => {}
        }
    }
    if !saw_version {
        return Err(SdpError::MissingVersion);
    }
    Ok(session)
}

fn parse_media(value: &str, line: usize) -> Result<SdpMedia, SdpError> {
    let parts: Vec<_> = value.split_whitespace().collect();
    if parts.len() < 4 {
        return Err(SdpError::InvalidMedia { line });
    }
    let port = parts[1]
        .split('/')
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or(SdpError::InvalidMedia { line })?;
    let payload_types = parts[3..]
        .iter()
        .map(|value| value.parse().map_err(|_| SdpError::InvalidMedia { line }))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SdpMedia {
        media_type: parts[0].into(),
        port,
        protocol: parts[2].into(),
        payload_types,
        control: None,
        range: None,
        frame_rate: None,
        frame_size: None,
        rtp_maps: BTreeMap::new(),
        fmtp: BTreeMap::new(),
        attributes: BTreeMap::new(),
    })
}

fn apply_media_attribute(
    media: &mut SdpMedia,
    name: &str,
    value: &str,
    line: usize,
) -> Result<(), SdpError> {
    match name {
        "control" => media.control = Some(value.into()),
        "range" => media.range = Some(value.into()),
        "framerate" => media.frame_rate = Some(value.into()),
        "framesize" => media.frame_size = value.split_once(' ').map(|(_, size)| size.into()),
        "rtpmap" => {
            let (payload, mapping) = value
                .split_once(' ')
                .ok_or(SdpError::InvalidRtpMap { line })?;
            let payload = payload
                .parse()
                .map_err(|_| SdpError::InvalidRtpMap { line })?;
            let mut mapping_parts = mapping.split('/');
            let encoding = mapping_parts
                .next()
                .filter(|value| !value.is_empty())
                .ok_or(SdpError::InvalidRtpMap { line })?;
            let clock_rate = mapping_parts
                .next()
                .and_then(|value| value.parse().ok())
                .ok_or(SdpError::InvalidRtpMap { line })?;
            let channels = mapping_parts.next().and_then(|value| value.parse().ok());
            media.rtp_maps.insert(
                payload,
                RtpMap {
                    encoding: encoding.into(),
                    clock_rate,
                    channels,
                },
            );
        }
        "fmtp" => {
            if let Some((payload, parameters)) = value.split_once(' ')
                && let Ok(payload) = payload.parse()
            {
                let entries = parameters
                    .split(';')
                    .filter_map(|entry| {
                        let (key, value) = entry.trim().split_once('=')?;
                        Some((key.trim().to_ascii_lowercase(), value.trim().into()))
                    })
                    .collect();
                media.fmtp.insert(payload, entries);
            }
        }
        _ => media
            .attributes
            .entry(name.into())
            .or_default()
            .push(value.into()),
    }
    Ok(())
}

pub fn resolve_control_uri(base: &str, control: &str) -> Result<String, SdpError> {
    if control == "*" {
        return Ok(base.into());
    }
    if Url::parse(control).is_ok() {
        return Ok(control.into());
    }
    let mut base_url = Url::parse(base).map_err(|_| SdpError::InvalidControlUri)?;
    if control.starts_with('/') {
        base_url.set_path(control);
        base_url.set_query(None);
        return Ok(base_url.to_string());
    }
    if !base_url.path().ends_with('/') {
        let path = format!("{}/", base_url.path());
        base_url.set_path(&path);
    }
    base_url
        .join(control)
        .map(|url| url.to_string())
        .map_err(|_| SdpError::InvalidControlUri)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "v=0\r\ns=Camera\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1; profile-level-id=42e01f\r\na=control:trackID=1\r\na=framerate:25\r\na=framesize:96 1920-1080\r\n";

    #[test]
    fn parses_h264_media_and_attributes() {
        let session = parse_sdp(SAMPLE).unwrap();
        assert_eq!(session.session_name.as_deref(), Some("Camera"));
        assert_eq!(session.media.len(), 1);
        let video = &session.media[0];
        assert_eq!(video.rtp_maps[&96].encoding, "H264");
        assert_eq!(video.rtp_maps[&96].clock_rate, 90_000);
        assert_eq!(video.control.as_deref(), Some("trackID=1"));
        assert_eq!(video.frame_size.as_deref(), Some("1920-1080"));
        assert_eq!(video.fmtp[&96]["packetization-mode"], "1");
    }

    #[test]
    fn resolves_relative_control_without_dropping_base_path() {
        assert_eq!(
            resolve_control_uri("rtsp://camera.test/main", "trackID=1").unwrap(),
            "rtsp://camera.test/main/trackID=1"
        );
    }

    #[test]
    fn rejects_sdp_without_version() {
        assert_eq!(
            parse_sdp("s=Missing version\r\n"),
            Err(SdpError::MissingVersion)
        );
    }
}
