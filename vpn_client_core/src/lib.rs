use base64::{engine::general_purpose, Engine as _};
use defguard_wireguard_rs::{
    host::Peer, key::Key, InterfaceConfiguration, Userspace, WGApi, WireguardInterfaceApi,
};
use rand::rngs::OsRng;
use std::ffi::{c_char, c_int, CStr, CString};
use tokio::runtime::Runtime;
use x25519_dalek::{PublicKey, StaticSecret};

// A struct to hold the generated key pair.
#[repr(C)]
pub struct VpnKeyPair {
    pub public_key: *mut c_char,
    pub private_key: *mut c_char,
}

#[no_mangle]
pub extern "C" fn vpn_generate_keypair() -> VpnKeyPair {
    // FIX: Use the non-deprecated function `random_from_rng`
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    VpnKeyPair {
        public_key: CString::new(general_purpose::STANDARD.encode(public.as_bytes()))
            .unwrap()
            .into_raw(),
        private_key: CString::new(general_purpose::STANDARD.encode(secret.to_bytes()))
            .unwrap()
            .into_raw(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn vpn_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

// The VpnClient struct now holds an Option<WGApi>.
// This allows us to have a state where the WGApi object doesn't exist (i.e., disconnected).
pub struct VpnClient {
    runtime: Runtime,
    ifname: String,
    wgapi: Option<WGApi<Userspace>>,
}

#[no_mangle]
pub extern "C" fn vpn_client_create() -> *mut VpnClient {
    // **FIX:** Use a unique name for the client interface to avoid conflicts with the server.
    let ifname = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        "wg_client".into()
    } else {
        "utun4".into()
    };

    match Runtime::new() {
        Ok(runtime) => {
            let client = VpnClient {
                runtime,
                ifname,
                wgapi: None, // Start in a disconnected state
            };
            Box::into_raw(Box::new(client))
        }
        Err(e) => {
            eprintln!("[VPN_CORE] Failed to create Tokio runtime: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn vpn_client_destroy(client_ptr: *mut VpnClient) {
    if !client_ptr.is_null() {
        // Taking ownership back from the raw pointer to allow Rust to drop it.
        // This will trigger the Drop implementation on WGApi if it still exists.
        let _ = Box::from_raw(client_ptr);
    }
}

#[no_mangle]
pub extern "C" fn vpn_client_connect(
    client_ptr: *mut VpnClient,
    client_privkey: *const c_char,
    client_ip: *const c_char,
    dns_server: *const c_char,
    server_pubkey: *const c_char,
    server_endpoint: *const c_char,
) -> c_int {
    if client_ptr.is_null() {
        eprintln!("[VPN_CORE] vpn_client_connect called with null client pointer");
        return -1;
    }
    let client = unsafe { &mut *client_ptr };

    // --- Convert C strings to Rust strings ---
    let client_privkey = unsafe { CStr::from_ptr(client_privkey) }
        .to_str()
        .unwrap_or("");
    let client_ip = unsafe { CStr::from_ptr(client_ip) }.to_str().unwrap_or("");
    let dns_server = unsafe { CStr::from_ptr(dns_server) }.to_str().unwrap_or("");
    let server_pubkey = unsafe { CStr::from_ptr(server_pubkey) }
        .to_str()
        .unwrap_or("");
    let server_endpoint = unsafe { CStr::from_ptr(server_endpoint) }
        .to_str()
        .unwrap_or("");

    if client_privkey.is_empty()
        || client_ip.is_empty()
        || server_pubkey.is_empty()
        || server_endpoint.is_empty()
    {
        eprintln!("[VPN_CORE] One or more connection parameters are empty");
        return -1;
    }

    // Proactively clean up any old interface before connecting.
    if let Ok(cleanup_api) = WGApi::<Userspace>::new(client.ifname.clone()) {
        let _ = cleanup_api.remove_interface();
    }

    let client_address = match client_ip.parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!(
                "[VPN_CORE] Failed to parse client_ip '{}': {:?}",
                client_ip, e
            );
            return -2;
        }
    };
    let server_socket_addr = match server_endpoint.parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!(
                "[VPN_CORE] Failed to parse server_endpoint '{}': {:?}",
                server_endpoint, e
            );
            return -3;
        }
    };

    client.runtime.block_on(async {
        // Here, you would implement platform-specific code to:
        // 1. Set the system DNS to `dns_server`.
        // 2. Add firewall rules for the kill switch.
        println!("[VPN_CORE] Received DNS server: {}", dns_server);
        println!(
            "[VPN_CORE] Kill switch would allow traffic ONLY to endpoint: {}",
            server_endpoint
        );

        let new_wgapi = match WGApi::<Userspace>::new(client.ifname.clone()) {
            Ok(api) => api,
            Err(e) => {
                eprintln!("[VPN_CORE] Failed to create WGApi: {:?}", e);
                return -4;
            }
        };

        let server_pubkey_bytes: [u8; 32] = match general_purpose::STANDARD.decode(server_pubkey) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            Ok(bytes) => {
                eprintln!(
                    "[VPN_CORE] Decoded server public key has invalid length: {}",
                    bytes.len()
                );
                return -5;
            }
            Err(e) => {
                eprintln!("[VPN_CORE] Failed to decode server public key: {:?}", e);
                return -5;
            }
        };

        let server_pubkey_key = Key::new(server_pubkey_bytes);
        let mut peer = Peer::new(server_pubkey_key);
        peer.endpoint = Some(server_socket_addr);
        peer.allowed_ips.push("0.0.0.0/0".parse().unwrap());

        let config = InterfaceConfiguration {
            name: client.ifname.clone(),
            prvkey: client_privkey.to_string(),
            addresses: vec![client_address],
            port: 0,
            peers: vec![peer],
            mtu: None,
        };

        if let Err(e) = new_wgapi.create_interface() {
            eprintln!("[VPN_CORE] Failed to create network interface: {:?}", e);
            return -6;
        }
        if let Err(e) = new_wgapi.configure_interface(&config) {
            eprintln!(
                "[VPN_CORE] Failed to configure WireGuard interface: {:?}",
                e
            );
            let _ = new_wgapi.remove_interface();
            return -7;
        }

        client.wgapi = Some(new_wgapi);
        0 // Success
    })
}

#[no_mangle]
pub extern "C" fn vpn_client_disconnect(client_ptr: *mut VpnClient) -> c_int {
    if client_ptr.is_null() {
        return -1;
    }
    let client = unsafe { &mut *client_ptr };

    // Here you would implement platform-specific code to:
    // 1. Revert the system DNS to its original settings.
    // 2. Remove the kill switch firewall rules.
    println!("[VPN_CORE] DNS and firewall rules would be reverted upon disconnect.");

    if let Some(wgapi) = client.wgapi.take() {
        // Dropping the wgapi object automatically triggers its cleanup.
        drop(wgapi);
    }

    0 // Success
}
