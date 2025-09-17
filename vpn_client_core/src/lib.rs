//! This is the shared core logic library for the VPN client.
//! It will be compiled as a C-compatible dynamic library so that native
//! frontends (like C++/Qt) can call its functions to manage the VPN connection.

use defguard_wireguard_rs::{
    host::Peer, key::Key, InterfaceConfiguration, Userspace, WGApi, WireguardInterfaceApi,
};
use std::ffi::{c_char, CStr};
use std::net::SocketAddr;
use tokio::runtime::Runtime;

/// Opaque struct to hold the state of the VPN client, including the WireGuard
/// API object and the Tokio runtime needed to execute async operations.
pub struct VpnClient {
    wgapi: WGApi<Userspace>,
    runtime: Runtime,
    // Store the interface name for later use.
    ifname: String,
}

/// Creates and initializes a new VpnClient instance.
///
/// This function must be called first. The returned pointer must be passed to
/// subsequent calls and finally to `vpn_client_destroy` to prevent memory leaks.
///
/// # Returns
/// A raw pointer to the VpnClient instance, or a null pointer if initialization fails.
#[no_mangle]
pub extern "C" fn vpn_client_create() -> *mut VpnClient {
    // We need a multithreaded Tokio runtime to drive the async WireGuard code.
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return std::ptr::null_mut(),
    };

    // The interface name is specific to the OS.
    let ifname: String = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        "wg_client".into()
    } else {
        "utun4".into() // Use a different name than the server if running on the same machine
    };

    let wgapi = match WGApi::<Userspace>::new(ifname.clone()) {
        Ok(api) => api,
        Err(_) => return std::ptr::null_mut(),
    };

    let client = VpnClient {
        wgapi,
        runtime,
        ifname,
    };

    // Box the client to place it on the heap, then return a raw pointer.
    // The caller is now responsible for this memory.
    Box::into_raw(Box::new(client))
}

/// Connects the VPN tunnel with the given configuration.
///
/// # Arguments
/// * `client` - A pointer returned by `vpn_client_create`.
/// * `private_key` - The client's private WireGuard key (base64 encoded).
/// * `client_ip` - The internal IP address for the client (e.g., "10.10.10.2/32").
/// * `server_pubkey` - The server's public WireGuard key (base64 encoded).
/// * `server_endpoint` - The server's public IP address and port (e.g., "1.2.3.4:51820").
///
/// # Returns
/// 0 on success, -1 on failure.
///
/// # Safety
/// The function is unsafe because it dereferences raw pointers and deals with C strings.
/// All C string pointers must be valid, null-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn vpn_client_connect(
    client: *mut VpnClient,
    private_key: *const c_char,
    client_ip: *const c_char,
    server_pubkey: *const c_char,
    server_endpoint: *const c_char,
) -> i32 {
    // Ensure the client pointer is not null.
    let client = if let Some(c) = client.as_mut() {
        c
    } else {
        return -1;
    };

    // Safely convert C strings to Rust strings.
    let private_key = CStr::from_ptr(private_key).to_str().unwrap_or_default();
    let client_ip = CStr::from_ptr(client_ip).to_str().unwrap_or_default();
    let server_pubkey = CStr::from_ptr(server_pubkey).to_str().unwrap_or_default();
    let server_endpoint_str = CStr::from_ptr(server_endpoint).to_str().unwrap_or_default();
    let server_endpoint: SocketAddr = server_endpoint_str.parse().unwrap();

    let server_pubkey_bytes: [u8; 32] =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, server_pubkey) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            _ => return -1,
        };

    // Configure the peer (the server).
    // Correctly create a Key struct before passing it to Peer::new.
    let server_pubkey = Key::new(server_pubkey_bytes);
    let mut peer = Peer::new(server_pubkey);
    peer.endpoint = Some(server_endpoint);
    // Route all traffic through the VPN.
    peer.allowed_ips.push("0.0.0.0/0".parse().unwrap());

    // Configure the client's interface.
    let config = InterfaceConfiguration {
        // Use the stored interface name.
        name: client.ifname.clone(),
        prvkey: private_key.to_string(),
        addresses: vec![client_ip.parse().unwrap()],
        peers: vec![peer],
        port: 0, // Let the OS choose the port
        mtu: None,
    };

    // Use the Tokio runtime to execute the async connection logic.
    client.runtime.block_on(async {
        if client.wgapi.create_interface().is_err() {
            return -1;
        }
        if client.wgapi.configure_interface(&config).is_err() {
            return -1;
        }
        0
    })
}

/// Disconnects the VPN tunnel.
///
/// # Arguments
/// * `client` - A pointer returned by `vpn_client_create`.
///
/// # Returns
/// 0 on success, -1 on failure.
///
/// # Safety
/// The function is unsafe because it dereferences a raw pointer.
#[no_mangle]
pub unsafe extern "C" fn vpn_client_disconnect(client: *mut VpnClient) -> i32 {
    let client = if let Some(c) = client.as_mut() {
        c
    } else {
        return -1;
    };

    client.runtime.block_on(async {
        if client.wgapi.remove_interface().is_err() {
            -1
        } else {
            0
        }
    })
}

/// Destroys the VpnClient instance and frees its memory.
///
/// This function must be called to clean up when the VPN client is no longer needed.
///
/// # Arguments
/// * `client` - A pointer returned by `vpn_client_create`.
///
/// # Safety
/// The function is unsafe because it dereferences a raw pointer. After this call,
/// the pointer is dangling and must not be used again.
#[no_mangle]
pub unsafe extern "C" fn vpn_client_destroy(client: *mut VpnClient) {
    if !client.is_null() {
        // Re-box the raw pointer to allow Rust's memory management to take over and drop it.
        drop(Box::from_raw(client));
    }
}

