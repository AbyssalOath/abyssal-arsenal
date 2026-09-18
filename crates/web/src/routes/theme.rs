use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;

use crate::common::require_csrf;
use crate::error::WebError;
use crate::theme::THEME_COOKIE;

#[derive(Deserialize)]
pub struct ThemeForm {
    csrf_token: String,
    theme: String,
}

pub async fn set(jar: CookieJar, Form(form): Form<ThemeForm>) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    let value = if form.theme == "light" {
        "light"
    } else {
        "dark"
    };
    let cookie = Cookie::build((THEME_COOKIE, value.to_string()))
        .path("/")
        .build();
    let jar = jar.add(cookie);
    Ok((jar, Redirect::to("/account")).into_response())
}
