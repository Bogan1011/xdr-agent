//! The agent's enrolled client certificate. Files and format match the Go
//! agent: agent.key, agent.crt and agent_id in the state directory, with
//! agent_id written last to mark enrollment as complete.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::pb;
use crate::transport;

#[derive(Clone)]
pub struct Identity {
    pub agent_id: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}

pub async fn load_or_enroll(cfg: &Config, host: pb::HostInfo) -> Result<Identity> {
    let ca_pem = fs::read(&cfg.ca_file).with_context(|| format!("read CA {}", cfg.ca_file.display()))?;
    match fs::read_to_string(cfg.state_path("agent_id")) {
        Ok(id) => Ok(Identity {
            agent_id: id.trim().to_string(),
            cert_pem: fs::read(cfg.state_path("agent.crt")).context("read agent.crt")?,
            key_pem: fs::read(cfg.state_path("agent.key")).context("read agent.key")?,
            ca_pem,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if cfg.enrollment_token.is_empty() {
                bail!("agent is not enrolled and no enrollment_token is configured");
            }
            enroll(cfg, ca_pem, host).await
        }
        Err(e) => Err(e.into()),
    }
}

async fn enroll(cfg: &Config, ca_pem: Vec<u8>, host: pb::HostInfo) -> Result<Identity> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host.hostname.clone());
    let csr = params.serialize_request(&key)?.pem()?;

    let channel = transport::enroll_channel(cfg, &ca_pem).await?;
    let mut client = pb::enrollment_service_client::EnrollmentServiceClient::new(channel);
    let mut req = tonic::Request::new(pb::EnrollRequest {
        enrollment_token: cfg.enrollment_token.clone(),
        csr_pem: csr.into_bytes(),
        host: Some(host),
    });
    req.set_timeout(Duration::from_secs(30));
    let resp = client.enroll(req).await.context("enroll")?.into_inner();

    let key_pem = key.serialize_pem().into_bytes();
    fs::create_dir_all(&cfg.state_dir)?;
    write_private(&cfg.state_path("agent.key"), &key_pem)?;
    write_private(&cfg.state_path("agent.crt"), &resp.certificate_pem)?;
    write_private(&cfg.state_path("agent_id"), resp.agent_id.as_bytes())?;
    Ok(Identity {
        agent_id: resp.agent_id,
        cert_pem: resp.certificate_pem,
        key_pem,
        ca_pem,
    })
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}
