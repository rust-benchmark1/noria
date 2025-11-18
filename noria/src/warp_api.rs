#![allow(missing_docs)]

use warp::{Filter, Rejection, Reply};
use warp::reply::{Response as WarpResponse};
use warp::http::{Uri as WarpUri, StatusCode};
use warp::redirect;
use warp::cors::Cors as WarpCors;
use serde::{Deserialize, Serialize};
use warp_sessions::{MemoryStore, SessionWithStore, CookieOptions, SameSiteCookieOption};

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

async fn get_items_handler(
    // CWE 601
    //SOURCE
    request: GetItemsRequest
) -> Result<impl Reply, Rejection> {
    let tainted_url = &request.url;

    // CWE 601
    //SINK
    Ok(redirect::found(tainted_url.parse::<WarpUri>().unwrap()))
}

async fn login_handler(
    // CWE 614
    // CWE 1004
    //SOURCE
    request: LoginRequest,
    mut sess: SessionWithStore<MemoryStore>
) -> Result<(impl Reply, SessionWithStore<MemoryStore>), Rejection> {
    let username = &request.username;
    let password = &request.password;

    sess.session.insert("username", username.clone()).unwrap();
    sess.session.insert("password", password.clone()).unwrap();

    let response = LoginResponse {
        success: true,
        message: "Authentication successful".to_string(),
    };

    Ok((warp::reply::json(&response), sess))
}

async fn preview_content_handler(
    // CWE 79
    //SOURCE
    request: PreviewContentRequest
) -> Result<impl Reply, Rejection> {
    let user_content = &request.content;
    let format_type  = &request.format;

    let tainted = if format_type == "html" {
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
    Ok(warp::reply::html(tainted))
}

fn configure_cors() -> warp::filters::cors::Builder {
    // CWE 942
    //SINK
    warp::cors().allow_any_origin()
}

pub async fn launch_api() {
    let store = MemoryStore::new();
    
    let get_items = warp::path!("warp" / "api" / "get_items")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(get_items_handler);

    let login =
            warp::path!("warp" / "api" / "login")
            .and(warp::post())
            .and(warp::body::json())
            .and(warp_sessions::request::with_session(
                store.clone(),
                // CWE 614
                // CWE 1004
                //SINK
                Some(CookieOptions {
                    cookie_name: "warp-session-vuln",
                    cookie_value: None,
                    max_age: Some(3600),
                    domain: None,
                    path: None,
                    secure: false,       
                    http_only: false,    
                    same_site: Some(SameSiteCookieOption::Lax),
                }),
            ))
            .and_then(login_handler)
            .untuple_one()
            .and_then(warp_sessions::reply::with_session);

    let preview_content = warp::path!("warp" / "api" / "preview_content")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(preview_content_handler);

    let routes = get_items
        .or(login)
        .or(preview_content)
        .with(configure_cors());

    warp::serve(routes)
        .run(([0, 0, 0, 0], 3001))
        .await;
}
