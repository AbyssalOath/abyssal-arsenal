use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub host_id: String,
    pub credential: String,
}

#[derive(Serialize)]
struct EnrollRequest<'a> {
    token: &'a str,
    name: &'a str,
}

#[derive(Deserialize)]
struct EnrollResponse {
    host_id: String,
    credential: String,
}

/// Loads persisted credentials if they exist; otherwise enrolls with the
/// control plane using a one-time token and persists the result. Idempotent
/// across restarts — once credentials exist, `enrollment_token` is ignored.
pub async fn load_or_enroll(
    control_plane_url: &str,
    enrollment_token: Option<String>,
    name: Option<String>,
    credentials_file: &Path,
) -> anyhow::Result<Credentials> {
    if let Ok(existing) = tokio::fs::read_to_string(credentials_file).await {
        tracing::info!(path = %credentials_file.display(), "using existing credentials");
        return Ok(serde_json::from_str(&existing)?);
    }

    let token = enrollment_token.ok_or_else(|| {
        anyhow::anyhow!(
            "no credentials found at {} and no --enrollment-token given; generate one from /admin/hosts",
            credentials_file.display()
        )
    })?;

    // The enrollment token is single-use and gets consumed by the control
    // plane the moment it accepts the request, before it even returns a
    // credential -- so if we can't actually save that credential locally,
    // we need to find out *before* spending the token, not after. A token
    // burned by a request that then fails to persist its own response
    // can't be reused; the operator would just have to generate a fresh
    // one anyway, so fail fast here instead.
    ensure_writable(credentials_file).await.map_err(|e| {
        anyhow::anyhow!(
            "cannot write credentials to {} (before even attempting enrollment): {e} -- \
             pass --credentials-file to point somewhere writable (e.g. under your home \
             directory for local testing), or run as a user/root that can write to this path",
            credentials_file.display()
        )
    })?;

    let host_name = name.unwrap_or_else(default_hostname);

    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/hosts/enroll",
        control_plane_url.trim_end_matches('/')
    );
    let response = client
        .post(&url)
        .json(&EnrollRequest {
            token: &token,
            name: &host_name,
        })
        .send()
        .await?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("enrollment rejected by control plane: {e}"))?
        .json::<EnrollResponse>()
        .await?;

    let credentials = Credentials {
        host_id: response.host_id,
        credential: response.credential,
    };
    persist(credentials_file, &credentials).await?;

    tracing::info!(host_id = %credentials.host_id, name = %host_name, "enrolled with control plane");
    Ok(credentials)
}

/// Proves the credentials file's directory exists and is actually writable
/// by creating and removing a hidden probe file in it, rather than writing
/// (and potentially leaving behind) an incomplete or empty real credentials
/// file if enrollment fails for some other reason afterward.
async fn ensure_writable(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    tokio::fs::create_dir_all(parent).await?;
    let probe = parent.join(".abyssal-agent-write-test");
    tokio::fs::write(&probe, b"").await?;
    let _ = tokio::fs::remove_file(&probe).await;
    Ok(())
}

async fn persist(path: &Path, credentials: &Credentials) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, serde_json::to_string_pretty(credentials)?).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(path).await?.permissions();
        perms.set_mode(0o600);
        tokio::fs::set_permissions(path, perms).await?;
    }

    Ok(())
}

fn default_hostname() -> String {
    #[cfg(unix)]
    if let Ok(contents) = std::fs::read_to_string("/etc/hostname")
        && !contents.trim().is_empty()
    {
        return contents.trim().to_string();
    }
    #[cfg(windows)]
    if let Ok(name) = std::env::var("COMPUTERNAME")
        && !name.trim().is_empty()
    {
        return name.trim().to_string();
    }
    "unknown-host".to_string()
}
