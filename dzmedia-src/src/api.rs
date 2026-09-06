#![allow(dead_code)]

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use std::{env, marker::Sized, time::{Instant, Duration}, sync::Arc};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use serde_json::{json, value::from_value};
use reqwest::{Client, Response, cookie::Jar, Url, header::ACCEPT};

#[derive(Deserialize)]
struct DeezerResponse {
    error: serde_json::Value,
    results: serde_json::Value,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[allow(non_camel_case_types)]
pub enum Format {
    AAC_64,
    AAC_96,
    FLAC,
    MP3_MISC,
    MP3_32,
    MP3_64,
    MP3_128,
    MP3_192,
    MP3_256,
    MP3_320,
    SBC_256,
    MP4_RA1,
    MP4_RA2,
    MP4_RA3,
}

#[derive(Serialize)]
struct DeezerFormat<'a> {
    cipher: &'a str,
    format: &'a Format,
}

#[derive(Error, Debug)]
pub enum APIError {
    #[error("reqwest error")]
    Reqwest(#[from] reqwest::Error),

    #[error("Deezer API error (code: {code:?}, message: {message:?})")]
    DeezerError {
        code: String,
        message: String,
    },

    #[error("Couldn't deserialize JSON response: {0}")]
    JSON(#[from] serde_json::error::Error)
}

#[derive(Clone)]
pub struct APIClient {
    client: Client,
    pub license_token: String,
    check_form: String,
    renew_instant: Option<Instant>,
}

impl APIClient {
    pub fn new() -> Self {
        match env::var("ARL") {
            Ok(arl) if !arl.trim().is_empty() => Self::new_with_arl(arl),
            _ => Self {
                client: Client::builder()
                    .no_proxy()
                    .connect_timeout(Duration::from_secs(5))
                    .timeout(Duration::from_secs(12))
                    .build()
                    .unwrap(),
                license_token: String::new(),
                check_form: String::new(),
                renew_instant: None,
            },
        }
    }

    pub fn new_with_arl(arl: String) -> Self {
        Self::new_with_arl_session(arl, String::new(), String::new())
    }

    pub fn new_with_arl_session(
        arl: String,
        check_form: String,
        license_token: String,
    ) -> Self {
        let builder = Client::builder().no_proxy();

        let cookie = format!("arl={}; Domain=.deezer.com; Path=/", arl);
        let comeback = "comeback=1; Domain=.deezer.com; Path=/";
        let url = "https://www.deezer.com".parse::<Url>().unwrap();

        let jar = Jar::default();
        jar.add_cookie_str(&cookie, &url);
        jar.add_cookie_str(comeback, &url);
        let builder = builder
            .cookie_provider(Arc::new(jar))
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(12));

        let renew_instant = if !license_token.is_empty() && !check_form.is_empty() {
            Some(Instant::now())
        } else {
            None
        };

        Self {
            client: builder.build().unwrap(),
            license_token,
            check_form,
            renew_instant,
        }
    }

    pub fn seed_session(&mut self, check_form: String, license_token: String) {
        if !check_form.is_empty() {
            self.check_form = check_form;
        }
        if !license_token.is_empty() {
            self.license_token = license_token;
            self.renew_instant = Some(Instant::now());
        }
    }

    pub fn session_tokens(&self) -> (String, String) {
        (self.check_form.clone(), self.license_token.clone())
    }

    pub async fn user_data(&mut self) -> Result<serde_json::Value, APIError> {
        self.no_renew_api_call("deezer.getUserData", &json!({})).await
    }

    async fn no_renew_api_call<P, T>(&mut self, method: &str, params: &P) -> Result<T, APIError>
        where P: Serialize + ?Sized,
              T: DeserializeOwned
    {
        let check_form;
        if method == "deezer.getUserData" {
            check_form = "null"
        } else {
            check_form = &self.check_form;
        }

        let url = "https://www.deezer.com/ajax/gw-light.php";
        let cid = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis().to_string())
            .unwrap_or_else(|_| "0".to_string());

        let body = serde_json::to_string(params)?;

        let resp = self.client.post(url)
            .header("Content-Type", "text/plain;charset=UTF-8")
            .body(body)
            .query(&[
                ("method", method),
                ("input", "3"),
                ("output", "3"),
                ("api_version", "1.0"),
                ("api_token", check_form),
                ("cid", cid.as_str()),
            ])
            .header(ACCEPT, "*/*")
            .header("Origin", "https://www.deezer.com")
            .header("Referer", "https://www.deezer.com/")
            .header("Sec-Fetch-Site", "same-origin")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Dest", "empty")
            .header("X-Requested-With", "XMLHttpRequest")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("sec-ch-ua", "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"")
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"Windows\"")
            .header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            )
            .send()
            .await?;

        let status = resp.status().as_u16();
        let text = resp.text().await?;
        let json: DeezerResponse = serde_json::from_str(&text).map_err(|e| {
            let snip: String = text.chars().take(200).collect();
            APIError::DeezerError {
                code: "bad_json".to_string(),
                message: format!("status:{status}; {e}; {snip}"),
            }
        })?;

        if let Some(error) = json.error.as_object() {
            for (code, message) in error {
                return Err(APIError::DeezerError {
                    code: code.clone(),
                    message: message.as_str().unwrap_or("error").to_string()
                })
            }
        }

        match from_value(json.results.clone()) {
            Ok(v) => Ok(v),
            Err(e) => Err(APIError::DeezerError {
                code: "parse_results".to_string(),
                message: format!("Error: {}; Data: {}", e, json.results),
            }),
        }
    }

    pub async fn api_call<P, T>(&mut self, method: &str, params: &P) -> Result<T, APIError>
        where P: Serialize + ?Sized,
              T: DeserializeOwned
    {
        if let Some(i) = self.renew_instant {
            if i.elapsed().as_secs() >= 3600 {
                self.renew().await?;
            }
        } else {
            self.renew().await?;
        }

        self.no_renew_api_call(method, params).await
    }

    /// Принудительное обновление токенов — вызывается при ошибках стрима
    pub async fn force_renew(&mut self) -> Result<(), APIError> {
        self.renew_instant = None; // сбрасываем таймер
        self.renew().await
    }

    async fn renew(&mut self) -> Result<(), APIError> {
        let user_data: serde_json::Value = self.user_data().await?;

        let check_form = user_data["checkForm"].as_str().unwrap_or("").to_string();
        let license_token = user_data
            .pointer("/USER/OPTIONS/license_token")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if check_form.is_empty() {
            return Err(APIError::DeezerError {
                code: "renew".to_string(),
                message: "checkForm missing in getUserData response".to_string(),
            });
        }
        if license_token.is_empty() {
            return Err(APIError::DeezerError {
                code: "renew".to_string(),
                message: "license_token missing in getUserData response".to_string(),
            });
        }

        self.check_form    = check_form;
        self.license_token = license_token;
        self.renew_instant = Some(Instant::now());
        Ok(())
    }

    pub async fn get_media(&self, formats: &Vec<Format>, track_tokens: Vec<&str>) -> Result<Response, reqwest::Error> {
        let formats: Vec<DeezerFormat> = formats.iter().map(|f| DeezerFormat { cipher: "BF_CBC_STRIPE", format: f }).collect();
        
        let req = json!({
            "license_token": self.license_token,
            "media": [{
                "formats": formats,
                "type": "FULL"
            }],
            "track_tokens": track_tokens
        });

        self.client
            .post("https://media.deezer.com/v1/get_url")
            .header(ACCEPT, "application/json")
            .header("Content-Type", "application/json")
            .header("Origin", "https://www.deezer.com")
            .header("Referer", "https://www.deezer.com/")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("sec-ch-ua", "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"")
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"Windows\"")
            .header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            )
            .json(&req)
            .send()
            .await
    }
}
