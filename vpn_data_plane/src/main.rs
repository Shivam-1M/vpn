//! Main entry point for the VPN Data Plane service.
//! This service is responsible for creating and managing a WireGuard interface
//! using a userspace implementation.

use defguard_wireguard_rs::{InterfaceConfiguration, Userspace, WGApi, WireguardInterfaceApi};
use std::error::Error;
use x25519_dalek::{PublicKey, StaticSecret};

// The base64 crate is brought in as a dependency of defguard_wireguard_rs,
// but we need to explicitly use it for key handling.
use base64::{engine::general_purpose, Engine as _};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("Initializing VPN Data Plane...");

    // Define the name for our WireGuard network interface.
    let ifname: String = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        "wg0".into()
    } else {
        // macOS uses a different naming convention for TUN devices.
        "utun3".into()
    };

    // --- Step 1 & 2: Create and Configure the WireGuard Interface ---

    // In a real application, this private key would be loaded securely.
    // NOTE: This key is a placeholder and must be 32 bytes, base64-encoded.
    let server_private_key_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let server_private_key_bytes: [u8; 32] = general_purpose::STANDARD.decode(server_private_key_b64)?
        .try_into()
        .expect("Private key is not 32 bytes long after base64 decoding");

    let secret = StaticSecret::from(server_private_key_bytes);
    let public_key = PublicKey::from(&secret);

    // The WGApi is the main entry point for managing the interface.
    // We specify `<Userspace>` to use the cross-platform userspace backend.
    let wgapi = WGApi::<Userspace>::new(ifname.clone())?;

    // Create the low-level OS network interface (e.g., a TUN device).
    wgapi.create_interface()?;

    // Define the configuration for our WireGuard interface.
    let config = InterfaceConfiguration {
        name: ifname,
        prvkey: server_private_key_b64.to_string(),
        // IP address for the server side of the tunnel.
        addresses: vec!["10.10.10.1/24".parse()?],
        port: 51820,
        peers: vec![], // No client peers configured yet.
        mtu: None,
    };

    // Apply the configuration to the interface. This brings the WireGuard tunnel online.
    wgapi.configure_interface(&config)?;

    tracing::info!(
        "WireGuard backend initialized. Public Key: {}",
    general_purpose::STANDARD.encode(public_key.as_bytes())
    );
    tracing::info!("VPN Data Plane is running. Listening on UDP port 51820.");

    // The defguard library now handles packet processing in the background.
    // We just need to keep the main thread alive.
    tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;

    // In a real app, you'd also want a graceful shutdown mechanism.
    // wgapi.remove_interface()?;

    Ok(())
}
