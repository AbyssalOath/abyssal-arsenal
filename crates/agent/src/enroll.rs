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
    match std::fs::read_to_string("/etc/hostname") {
        Ok(contents) if !contents.trim().is_empty() => contents.trim().to_string(),
        _ => "unknown-host".to_string(),
    }
}
