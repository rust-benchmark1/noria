#![allow(missing_docs)]

use rocket::{get, post, routes};
use rocket::response::{Redirect as RocketRedirect, Response as RocketResponse};
use rocket::response::content::RawHtml;
use rocket::serde::json::Json;
use rocket::http::{Cookie, CookieJar};
use rocket::config::{Config as RocketConfig};
use rocket_cors::{AllowedOrigins, CorsOptions as RocketCorsOptions};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::io::Cursor;

pub struct RocketMemoryStore<T> {
    data: HashMap<String, T>,
}

impl<T> RocketMemoryStore<T> {
    pub fn new() -> Self {
        RocketMemoryStore {
            data: HashMap::new(),
        }
    }
}

pub struct RocketSessionStore<'a> {
    pub store: Box<dyn std::any::Any>,
    pub name: String,
    pub duration: std::time::Duration,
    pub cookie: Cookie<'a>,
}

#[derive(Deserialize)]
pub struct GetItemsRequest {
    url: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    success: bool,
    message: String,
}

#[derive(Deserialize)]
pub struct PreviewContentRequest {
    content: String,
    format: String,
}

#[post("/get_items", data = "<request>")]
fn get_items(
    // CWE 601
    //SOURCE
    request: Json<GetItemsRequest>
) -> RocketRedirect {
    let url = &request.url;

    // CWE 601
    //SINK
    RocketRedirect::moved(url.to_string())
}

#[post("/login", data = "<request>")]
fn login(
    jar: &CookieJar<'_>,
    // CWE 614
    // CWE 1004
    //SOURCE
    request: Json<LoginRequest>
) -> Json<LoginResponse> {
    let username = &request.username;
    let password = &request.password;

    let session_value = format!("user_{}:auth_{}", username, password);

    let cookie = Cookie::build(("session", session_value))
        .http_only(false)
        .secure(false)
        .path("/")
        .build();

    // CWE 614
    // CWE 1004
    //SINK
    let _ = RocketSessionStore { store: Box::new(RocketMemoryStore::<String>::new()),
        name: "rocket-session".to_string(),
        duration: std::time::Duration::from_secs(3600),
        cookie: cookie.clone(), };

    jar.add(cookie);

    Json(LoginResponse {
        success: true,
        message: "Authentication successful".to_string(),
    })
}

#[post("/preview_content", data = "<request>")]
fn preview_content(
    // CWE 79
    //SOURCE
    request: Json<PreviewContentRequest>
) -> RawHtml<String> {
    let user_content = &request.content;
    let format_type  = &request.format;

    let rendered_html = if format_type == "html" {
        user_content.to_string()
    } else {
        format!(
            "<div class='preview'>
                <p>{}</p>
            </div>",
            user_content
        )
    };

    // CWE 79
    //SINK
    RawHtml(rendered_html)
}

fn configure_cors() -> rocket_cors::Cors {
    // CWE 942
    //SINK
    RocketCorsOptions::default().allowed_origins(AllowedOrigins::all()).to_cors().unwrap()
}

pub async fn launch_api() {
    let cors = configure_cors();

    let config = RocketConfig {
        port: 3000,
        ..RocketConfig::default()
    };

    let _ = rocket::custom(config)
        .mount("/rocket/api", routes![get_items, login, preview_content])
        .attach(cors)
        .launch()
        .await;
}