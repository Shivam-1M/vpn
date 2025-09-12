//! Main entry point for the VPN Data Plane service.
//! This service is responsible for creating a virtual TUN network interface,
//! configuring it with WireGuard, and processing all encrypted network packets
//! at high speed.

use std::error::Error;

// This is the main entry point for our asynchronous application.
// The #[tokio::main] attribute transforms the async main function
// into a synchronous main function that sets up and runs the Tokio runtime.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize the tracing subscriber for structured logging.
    // This allows us to see what's happening inside the application.
    tracing_subscriber::fmt::init();

    tracing::info!("Initializing VPN Data Plane...");

    // --- TODO: Step 1 ---
    // Create an asynchronous TUN interface. This will be our virtual network card
    // that the operating system sees. All traffic for the VPN will go through this.
    // We will use the `tokio-tun` crate for this.

    // --- TODO: Step 2 ---
    // Initialize and configure the WireGuard backend using `defguard_wireguard_rs`.
    // This involves setting up the private key for the server and the listen port.

    // --- TODO: Step 3 ---
    // Connect the TUN interface with the WireGuard backend. This is the core loop
    // where we will read packets from the TUN device, pass them to WireGuard for
    // encryption/decryption, and send them out to the internet (and vice-versa).

    tracing::info!("VPN Data Plane started successfully. (Placeholder)");

    // For now, the application just prints a message and exits.
    // In the future, this will be an infinite loop that runs the VPN service.
    Ok(())
}