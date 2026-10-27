//! Platform-independent core of the XDR agent: configuration, identity,
//! the local event bus, the durable priority queue, the policy cache and the
//! gRPC/mTLS transport. Operating system specifics live behind [`platform`].

pub mod agent;
pub mod bus;
pub mod commands;
pub mod config;
pub mod heartbeat;
pub mod identity;
pub mod live;
pub mod platform;
pub mod queue;
pub mod transport;
pub mod update;
pub mod uploader;

pub use xdr_proto::v1 as pb;

/// SecurityEvent envelope version produced by this agent (docs/architecture.md).
pub const SCHEMA_VERSION: u32 = 1;

/// Agent version reported to the console.
/// The release build sets XDR_VERSION to the console's release version, so
/// the console's update check compares like with like.
pub const VERSION: &str = match option_env!("XDR_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};
