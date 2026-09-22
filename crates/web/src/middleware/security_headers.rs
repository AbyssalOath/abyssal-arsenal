use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

/// Applied to every response. The UI never being the security boundary means
/// these headers matter regardless of what a given page renders.
pub async fn apply(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            // style-src needs 'unsafe-inline' because this app's templates
            // use plain `style="..."` attributes throughout (there's no
            // nonce/hash plumbing through Askama to avoid it) -- without
            // it, a CSP-enforcing browser silently drops every inline
            // style on every page, which is a layout bug, not a defended
            // attack surface; inline styles can't execute script. script-src
            // stays strict with no such exception: the two pages that need
            // any client-side JS at all (Panopticon's scan progress and
            // the SSH deploy status page) load it from same-origin
            // `/static/*.js` files instead of an inline <script> block
            // specifically so script-src never needs loosening.
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'",
        ),
    );
    response
}
