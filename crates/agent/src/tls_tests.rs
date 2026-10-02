//! End-to-end TLS tests against certificates produced by the control plane's
//! own CA code (`abyssal-internal-ca`, what `/admin/health` issues and
//! renews), using the agent's own `tls::Trust` -- the same
//! `rustls::ClientConfig` enrollment and the WebSocket use. This is the test
//! that would have caught the original `CaUsedAsEndEntity` failure: a
//! Windows-side `Invoke-WebRequest` succeeding proves nothing about what
//! webpki accepts.

use std::sync::Arc;

use abyssal_internal_ca::{self as ca, Material};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::tls::{self, Failure, Trust};

fn certs(pem: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .unwrap()
}

fn internal(addresses: &str) -> (Material, Material) {
    let addresses = ca::parse_addresses(addresses).unwrap();
    let authority = ca::create_ca(&addresses).unwrap();
    let server = ca::issue_server_cert(&authority, &addresses).unwrap();
    (authority, server)
}

/// What the pre-CA installer produced: a self-signed `CA:TRUE` certificate
/// served as the TLS leaf (`openssl req -x509` defaults).
fn legacy(ip: &str) -> Material {
    let mut params = rcgen::CertificateParams::new(vec![ip.to_string()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    Material {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// An HTTPS server answering any request with `200 ok`, serving the given
/// chain/key the way Caddy does.
async fn serve(server: &Material) -> u16 {
    let chain = certs(&server.cert_pem);
    let key = PrivateKeyDer::from_pem_slice(server.key_pem.as_bytes()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

fn trust_only(pem: &str) -> Trust {
    // No native roots: only the CA under test may make this succeed.
    Trust::from_parts(Vec::new(), certs(pem)).unwrap()
}

async fn https_get(trust: &Trust, url: &str) -> anyhow::Result<String> {
    let client = trust.http_client(reqwest::Client::builder())?;
    Ok(client.get(url).send().await?.text().await?)
}

#[tokio::test]
async fn agent_client_accepts_the_internal_ca_in_ip_mode() {
    let (authority, server) = internal("127.0.0.1");
    let port = serve(&server).await;
    let trust = trust_only(&authority.cert_pem);

    // reqwest path (enrollment).
    let body = https_get(&trust, &format!("https://127.0.0.1:{port}/"))
        .await
        .expect("enrollment-style HTTPS request must succeed with only the CA trusted");
    assert_eq!(body, "ok");

    // Raw rustls path, the config tokio-tungstenite gets for the WebSocket.
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    tokio_rustls::TlsConnector::from(trust.rustls_config())
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .expect("WebSocket TLS handshake must succeed with only the CA trusted");
}

#[tokio::test]
async fn agent_client_accepts_the_internal_ca_in_fqdn_mode() {
    let (authority, server) = internal("localhost");
    let port = serve(&server).await;
    let trust = trust_only(&authority.cert_pem);

    let body = https_get(&trust, &format!("https://localhost:{port}/"))
        .await
        .expect("FQDN-mode cert must validate by name");
    assert_eq!(body, "ok");

    // Browsing by an address that isn't on the cert is a name mismatch, and
    // is reported as one.
    let err = https_get(&trust, &format!("https://127.0.0.1:{port}/"))
        .await
        .unwrap_err();
    assert_eq!(tls::classify(&err), Failure::TlsNameMismatch, "{err:#}");
}

#[tokio::test]
async fn one_certificate_can_cover_an_ip_and_a_name() {
    let (authority, server) = internal("127.0.0.1 localhost");
    let port = serve(&server).await;
    let trust = trust_only(&authority.cert_pem);
    for host in ["127.0.0.1", "localhost"] {
        assert_eq!(
            https_get(&trust, &format!("https://{host}:{port}/"))
                .await
                .unwrap(),
            "ok"
        );
    }
}

#[tokio::test]
async fn a_rotation_bundle_trusts_both_the_old_and_new_ca() {
    // During a CA rotation the agent's ca.pem holds the active and the
    // pending CA, so it keeps connecting across the switch-over.
    let (old_ca, old_server) = internal("127.0.0.1");
    let (new_ca, new_server) = internal("127.0.0.1");
    let bundle = format!("{}{}", old_ca.cert_pem, new_ca.cert_pem);
    let trust = trust_only(&bundle);
    for server in [&old_server, &new_server] {
        let port = serve(server).await;
        assert_eq!(
            https_get(&trust, &format!("https://127.0.0.1:{port}/"))
                .await
                .unwrap(),
            "ok"
        );
    }
}

#[tokio::test]
async fn legacy_self_signed_cert_is_rejected_as_ca_used_as_end_entity() {
    let old = legacy("127.0.0.1");
    let port = serve(&old).await;
    // Even with the legacy cert itself as the trust anchor -- what importing
    // it into the OS root store amounts to -- webpki refuses it as a leaf.
    let trust = trust_only(&old.cert_pem);

    let err = https_get(&trust, &format!("https://127.0.0.1:{port}/"))
        .await
        .unwrap_err();
    assert_eq!(
        tls::classify(&err),
        Failure::TlsCaUsedAsEndEntity,
        "{err:#}"
    );
}

#[tokio::test]
async fn a_different_ca_is_reported_as_untrusted() {
    let (_, served) = internal("127.0.0.1");
    let (other_ca, _) = internal("127.0.0.1");
    let port = serve(&served).await;
    let trust = trust_only(&other_ca.cert_pem);

    let err = https_get(&trust, &format!("https://127.0.0.1:{port}/"))
        .await
        .unwrap_err();
    assert_eq!(tls::classify(&err), Failure::TlsUntrusted, "{err:#}");
}

#[test]
fn fingerprints_agree_with_the_control_plane() {
    let (authority, _) = internal("127.0.0.1");
    let ours = tls::fingerprint(&certs(&authority.cert_pem)[0]);
    let theirs = ca::inspect(&authority.cert_pem).unwrap().fingerprint;
    assert_eq!(ours, theirs);
    assert!(tls::verify_fingerprint(&certs(&authority.cert_pem), &theirs).is_ok());
    assert!(tls::verify_fingerprint(&certs(&authority.cert_pem), &"00".repeat(32)).is_err());
}

/// One test (not several) because it drives the process-wide trust slot.
#[test]
fn pushed_ca_bundles_update_the_ca_file_and_live_trust() {
    let (old_ca, _) = internal("127.0.0.1");
    let (new_ca, _) = internal("127.0.0.1");

    // Installed without --ca-cert: nothing of ours to change.
    tls::set_process_trust(
        Trust::from_parts(Vec::new(), certs(&old_ca.cert_pem)).unwrap(),
        None,
    );
    let result = tls::update_trusted_ca(&new_ca.cert_pem).unwrap();
    assert_eq!(result.status, "unmanaged");

    let dir = std::env::temp_dir().join(format!("abyssal-agent-trust-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ca.pem");
    std::fs::write(&path, &old_ca.cert_pem).unwrap();
    tls::set_process_trust(trust_only(&old_ca.cert_pem), Some(path.clone()));

    let bundle = format!("{}{}", old_ca.cert_pem, new_ca.cert_pem);
    let result = tls::update_trusted_ca(&bundle).unwrap();
    assert_eq!(result.status, "updated");
    assert_eq!(result.fingerprints.len(), 2);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), bundle);
    assert!(!dir.join("ca.pem.new").exists());
    assert_eq!(tls::update_trusted_ca(&bundle).unwrap().status, "unchanged");

    // A key smuggled into the bundle is refused and nothing changes.
    let with_key = format!("{}{}", new_ca.cert_pem, new_ca.key_pem);
    assert!(tls::update_trusted_ca(&with_key).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), bundle);

    let _ = std::fs::remove_dir_all(&dir);
}
