//! gRPC channels to the console over TLS 1.3, with the agent certificate
//! for every call after enrollment.

use std::time::Duration;

use anyhow::Result;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity as TlsIdentity};

use crate::config::Config;
use crate::identity::Identity;
use crate::pb::agent_service_client::AgentServiceClient;

/// Detection content carries the hash block list, up to 16 MiB.
const MAX_RECV: usize = 32 << 20;

fn endpoint(addr: &str, tls: ClientTlsConfig) -> Result<Endpoint> {
    Ok(Endpoint::from_shared(format!("https://{addr}"))?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(15))
        .http2_keep_alive_interval(Duration::from_secs(60))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true))
}

pub async fn enroll_channel(cfg: &Config, ca_pem: &[u8]) -> Result<Channel> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        .domain_name(cfg.tls_name(&cfg.enroll_server));
    Ok(endpoint(&cfg.enroll_server, tls)?.connect().await?)
}

/// A lazily connected channel: calls fail while the console is unreachable
/// and succeed again once it is back, without rebuilding the client.
pub fn agent_client(cfg: &Config, id: &Identity) -> Result<AgentServiceClient<Channel>> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&id.ca_pem))
        .identity(TlsIdentity::from_pem(&id.cert_pem, &id.key_pem))
        .domain_name(cfg.tls_name(&cfg.server));
    let channel = endpoint(&cfg.server, tls)?.connect_lazy();
    Ok(AgentServiceClient::new(channel)
        .send_compressed(tonic::codec::CompressionEncoding::Gzip)
        .accept_compressed(tonic::codec::CompressionEncoding::Gzip)
        .max_decoding_message_size(MAX_RECV))
}
