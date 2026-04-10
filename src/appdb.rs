// appdb.to link session + configure API (mirrors JIT Pair Electron renderer)

use base64::{engine::general_purpose::STANDARD, Engine};
use egui::ColorImage;
use qrcode::{Color, QrCode};
use serde::Deserialize;
use serde_json::Value;

const GET_LINK_SESSION: &str = "https://api.dbservices.to/v1.7/get_link_session/";

#[derive(Debug, Deserialize)]
pub struct GetLinkSessionResponse {
    pub success: bool,
    pub data: Option<LinkSessionData>,
    #[serde(default)]
    pub errors: Vec<ApiError>,
}

#[derive(Debug, Deserialize)]
pub struct LinkSessionData {
    pub uuid: String,
    /// Unix timestamp (seconds); API returns a number, not a string.
    #[allow(dead_code)]
    pub expires_at: Option<i64>,
    pub link_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApiError {
    pub code: Option<String>,
    pub translated: Option<String>,
}

pub async fn fetch_link_session(uuid: Option<&str>) -> Result<GetLinkSessionResponse, String> {
    let client = reqwest::Client::new();
    let mut req = client.get(GET_LINK_SESSION);
    if let Some(u) = uuid {
        req = req.query(&[("uuid", u)]);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let text = resp.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("get_link_session JSON: {e}: {text}"))
}

pub fn configure_url(link_token: &str) -> String {
    format!("https://api.dbservices.to/v1.7/configure/?lt={link_token}")
}

/// Base64 for `params[pairing_file]`, matching main.js `base64_encode(stdout)`:
/// UTF-8 string bytes, with trailing line endings trimmed (typical CLI stdout).
fn appdb_pairing_base64(pairing_bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(pairing_bytes) {
        STANDARD.encode(s.trim_end().as_bytes())
    } else {
        STANDARD.encode(pairing_bytes)
    }
}

fn json_success_flag(v: &Value) -> bool {
    match v.get("success") {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => {
            n.as_u64().is_some_and(|x| x != 0) || n.as_i64().is_some_and(|x| x != 0)
        }
        _ => false,
    }
}

fn first_api_error_message(v: &Value) -> Option<String> {
    v.get("errors")?.as_array()?.first().and_then(|o| {
        o.get("translated")
            .or_else(|| o.get("code"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
    })
}

/// POST configure — same request as renderer.js `attach_pairing_file`:
/// `Content-Type: application/x-www-form-urlencoded`,
/// body `params[pairing_file]=` + encodeURIComponent(base64).
pub async fn upload_pairing_file(link_token: &str, pairing_bytes: &[u8]) -> Result<(), String> {
    let b64 = appdb_pairing_base64(pairing_bytes);
    let url = configure_url(link_token);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .form(&[("params[pairing_file]", b64.as_str())])
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;

    let v: Value = serde_json::from_str(&text).map_err(|e| {
        format!(
            "configure: invalid JSON (HTTP {status}): {e}; body: {}",
            text.chars().take(400).collect::<String>()
        )
    })?;

    if !status.is_success() {
        return Err(first_api_error_message(&v).unwrap_or_else(|| {
            format!(
                "HTTP {status}: {}",
                text.chars().take(400).collect::<String>()
            )
        }));
    }

    let success = json_success_flag(&v);

    if let Some(errors) = v.get("errors").and_then(|e| e.as_array()) {
        if !errors.is_empty() {
            let msg = first_api_error_message(&v)
                .unwrap_or_else(|| "appdb returned errors".to_string());
            return Err(msg);
        }
    }

    if !success {
        return Err(first_api_error_message(&v).unwrap_or_else(|| {
            "appdb reported success=false (no error details)".to_string()
        }));
    }

    Ok(())
}

pub fn qr_code_url(uuid: &str) -> String {
    format!("https://appdb.to/link-qr/?uuid={}", uuid)
}

pub fn qr_code_color_image(url: &str) -> Result<ColorImage, String> {
    let code = QrCode::new(url.as_bytes()).map_err(|e| e.to_string())?;
    let width = code.width();
    let scale = 4_usize;
    let px = width * scale;
    let mut rgba = vec![255_u8; px * px * 4];
    for y in 0..width {
        for x in 0..width {
            let dark = code[(x, y)] == Color::Dark;
            let (r, g, b) = if dark {
                (0_u8, 0_u8, 0_u8)
            } else {
                (255_u8, 255_u8, 255_u8)
            };
            for dy in 0..scale {
                for dx in 0..scale {
                    let ox = x * scale + dx;
                    let oy = y * scale + dy;
                    let i = (oy * px + ox) * 4;
                    rgba[i] = r;
                    rgba[i + 1] = g;
                    rgba[i + 2] = b;
                    rgba[i + 3] = 255;
                }
            }
        }
    }
    Ok(ColorImage::from_rgba_unmultiplied([px, px], &rgba))
}
