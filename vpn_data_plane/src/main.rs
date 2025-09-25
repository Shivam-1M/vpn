use base64::{engine::general_purpose, Engine as _};
use defguard_wireguard_rs::{
    host::Peer, key::Key, InterfaceConfiguration, Userspace, WGApi, WireguardInterfaceApi,
};
use log;
use std::env;
use std::error::Error;
use std::sync::Arc;
use tonic::{
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};
use x25519_dalek::{PublicKey, StaticSecret};

pub mod vpn {
    tonic::include_proto!("vpn");
}
use vpn::vpn_manager_server::{VpnManager, VpnManagerServer};
use vpn::{PeerRequest, PeerResponse};

/// The gRPC service for managing the VPN.
pub struct VpnManagerService {
    wgapi: Arc<WGApi<Userspace>>,
}

#[tonic::async_trait]
impl VpnManager for VpnManagerService {
    /// Adds a peer to the VPN.
    async fn add_peer(
        &self,
        request: Request<PeerRequest>,
    ) -> Result<Response<PeerResponse>, Status> {
        let inner = request.into_inner();
        let public_key_b64 = inner.public_key;
        let ip_address = inner.ip_address; // Get the IP from the request

        log::info!(
            "gRPC: Received AddPeer request for key: {} with IP: {}",
            public_key_b64,
            ip_address
        );

        let public_key_bytes = match general_purpose::STANDARD.decode(&public_key_b64) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => return Err(Status::invalid_argument("Invalid public key format")),
        };

        // Validate the received IP address
        let allowed_ip = match ip_address.parse() {
            Ok(ip) => ip,
            Err(_) => return Err(Status::invalid_argument("Invalid IP address format")),
        };

        let public_key = defguard_wireguard_rs::key::Key::new(public_key_bytes);
        let mut peer = Peer::new(public_key);
        peer.allowed_ips.push(allowed_ip);

        if let Err(e) = self.wgapi.configure_peer(&peer) {
            log::error!("gRPC: Failed to configure peer: {}", e);
            return Err(Status::internal("Failed to configure peer"));
        }

        log::info!(
            "gRPC: Successfully configured peer with key: {}",
            public_key_b64
        );
        let reply = PeerResponse {
            success: true,
            message: format!("Peer {} added successfully", public_key_b64),
        };
        Ok(Response::new(reply))
    }

    /// Removes a peer from the VPN.
    async fn remove_peer(
        &self,
        request: Request<PeerRequest>,
    ) -> Result<Response<PeerResponse>, Status> {
        let public_key_b64 = request.into_inner().public_key;
        log::info!(
            "gRPC: Received RemovePeer request for key: {}",
            public_key_b64
        );

        let public_key_bytes = match general_purpose::STANDARD.decode(&public_key_b64) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                return Err(Status::invalid_argument(
                    "Invalid public key format for removal",
                ));
            }
        };
        let peer_key = Key::new(public_key_bytes);

        if let Err(e) = self.wgapi.remove_peer(&peer_key) {
            log::error!("gRPC: Failed to remove peer: {}", e);
            return Err(Status::internal("Failed to remove peer from interface"));
        }

        log::info!(
            "gRPC: Successfully removed peer with key: {}",
            public_key_b64
        );
        let reply = PeerResponse {
            success: true,
            message: format!("Peer {} removed successfully", public_key_b64),
        };
        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    log::info!("Initializing VPN Data Plane...");

    let ifname: String = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        "wg0".into()
    } else {
        "utun3".into()
    };

    if let Ok(cleanup_api) = WGApi::<Userspace>::new(ifname.clone()) {
        if let Err(e) = cleanup_api.remove_interface() {
            log::warn!(
                "Attempted to clean up stale interface, but it might not have existed: {}",
                e
            );
        } else {
            log::info!("Successfully cleaned up stale '{}' interface.", ifname);
        }
    }

    let server_private_key_b64 =
        env::var("WG_PRIVATE_KEY").expect("FATAL: WG_PRIVATE_KEY environment variable not set.");

    let server_private_key_bytes: [u8; 32] = general_purpose::STANDARD
        .decode(&server_private_key_b64)?
        .try_into()
        .expect("Private key is not 32 bytes long after base64 decoding");

    let secret = StaticSecret::from(server_private_key_bytes);
    let public_key = PublicKey::from(&secret);

    let wgapi = Arc::new(WGApi::<Userspace>::new(ifname.clone())?);
    wgapi.create_interface()?;

    let config = InterfaceConfiguration {
        name: ifname,
        prvkey: server_private_key_b64.to_string(),
        addresses: vec!["10.10.10.1/24".parse()?],
        port: 51820,
        peers: vec![],
        mtu: None,
    };
    wgapi.configure_interface(&config)?;

    log::info!(
        "WireGuard backend initialized. Public Key: {}",
        general_purpose::STANDARD.encode(public_key.as_bytes())
    );
    log::info!("WireGuard listening on UDP port 51820.");

    let grpc_addr = "0.0.0.0:50051".parse()?;
    let vpn_service = VpnManagerService {
        wgapi: Arc::clone(&wgapi),
    };
    let grpc_server = VpnManagerServer::new(vpn_service);

    log::info!("Loading TLS certificates...");

    let cert = tokio::fs::read("../certs/server.pem").await?;
    let key = tokio::fs::read("../certs/server.key").await?;
    let identity = Identity::from_pem(cert, key);
    let tls_config = ServerTlsConfig::new().identity(identity);

    log::info!("gRPC server listening securely on {}", grpc_addr);

    Server::builder()
        .tls_config(tls_config)?
        .add_service(grpc_server)
        .serve(grpc_addr)
        .await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;

    Ok(())
}
