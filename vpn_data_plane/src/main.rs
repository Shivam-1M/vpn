//! Main entry point for the VPN Data Plane service.
//! This service is responsible for creating a virtual TUN network interface,
//! configuring it with WireGuard, and processing all encrypted network packets
//! at high speed.

use std::error::Error;
use tokio_tun::TunBuilder;

// This is the main entry point for our asynchronous application.
// The #[tokio::main] attribute transforms the async main function
// into a synchronous main function that sets up and runs the Tokio runtime.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize the tracing subscriber for structured logging.
    // This allows us to see what's happening inside the application.
    tracing_subscriber::fmt::init();

    tracing::info!("Initializing VPN Data Plane...");

    // --- Step 1: Create an asynchronous TUN interface ---
    // This creates a new virtual network interface. We give it a name,
    // set the IP address and netmask for our side of the tunnel, and bring it up.
    // On Linux, this will create a device like 'tun0'. You'll need to run this
    // with `sudo` for it to have the necessary permissions to create the interface.
    let tun = TunBuilder::new()
        .name("wg0") // Interface name
        .up() // Bring the interface up
        .build()?;

    let tun = tun.into_iter().next().unwrap();
    
    tracing::info!("Successfully created TUN device: {}", tun.name());

    // --- TODO: Step 2 ---
    // Initialize and configure the WireGuard backend using `defguard_wireguard_rs`.
    // This involves setting up the private key for the server and the listen port.

    // --- TODO: Step 3 ---
    // Connect the TUN interface with the WireGuard backend. This is the core loop
    // where we will read packets from the TUN device, pass them to WireGuard for
    // encryption/decryption, and send them out to the internet (and vice-versa).

    tracing::info!("VPN Data Plane is running. (TUN device created)");

    // The application will now wait indefinitely. We will replace this later
    // with the main packet processing loop.
    tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;

    Ok(())
}
