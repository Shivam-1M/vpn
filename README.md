# VPN Project

A secure, multi-component VPN system built with WireGuard, featuring a control plane for user management, a data plane for network handling, and cross-platform client applications.

## Project Description

This project implements a complete VPN solution using WireGuard as the underlying tunneling protocol. It consists of several components:

- **Control Plane**: A Go-based REST API server that handles user authentication, device management, and IP address allocation
- **Data Plane**: A Rust-based gRPC service that manages the WireGuard interface and peer connections
- **Client Core**: A Rust library providing VPN connection functionality with a C-compatible API
- **Desktop Client**: A Qt-based GUI application for Windows/Linux that provides an easy-to-use interface for VPN management

The system supports user registration, device authentication, secure peer management, and includes features like kill switch protection and automatic reconnection.

## Features

- User authentication with JWT tokens (including Email/Password Registration)
- Device registration and management
- Automatic IP address management (IPAM)
- Secure gRPC communication between control and data planes
- TLS-encrypted connections
- IPv6 Support (Planned)
- Cross-platform Kill Switch (Windows & Linux) to prevent IP leaks
- Cross-platform desktop client (Windows & Linux)
- PostgreSQL database for persistent storage
- Docker-based deployment for database

## Project Structure

```
vpn/
├── certs/                          # TLS certificates for secure communication
│   ├── ca.key, ca.pem             # Certificate Authority files
│   ├── server.key, server.pem     # Server certificate files
│   └── openssl.cnf                # OpenSSL configuration
├── vpn_control_plane/              # Go-based control plane
│   ├── main.go                    # Main application entry point
│   ├── vpn/                       # Generated gRPC code
│   │   ├── vpn_grpc.pb.go
│   │   └── vpn.pb.go
│   ├── vpn.proto                  # gRPC service definition
│   ├── go.mod                     # Go module dependencies
│   └── docker-compose.yml         # PostgreSQL database setup
├── vpn_data_plane/                 # Rust-based data plane
│   ├── src/main.rs                # WireGuard interface management
│   ├── Cargo.toml                 # Rust dependencies
│   └── vpn.proto                  # gRPC service definition
├── vpn_client_core/                # Rust VPN client library
│   ├── src/lib.rs                 # C-compatible VPN API
│   ├── Cargo.toml                 # Rust dependencies
│   └── target/                    # Build artifacts
└── vpn_desktop_client/             # Qt-based desktop client
    ├── CMakeLists.txt             # CMake build configuration
    ├── src/                       # C++ source files
    │   ├── main.cpp
    │   ├── mainwindow.cpp, .h
    │   ├── cryptomanager.cpp, .h
    │   └── mainwindow.ui          # Qt UI definition
    ├── recovery_tool/             # Recovery utility
    └── build/                     # Build artifacts
```

## Prerequisites

### System Requirements

- Linux (Ubuntu/Debian recommended) or Windows
- Rust 1.70+ (for data plane and client core)
- Go 1.21+ (for control plane)
- CMake 3.16+ (for desktop client)
- Qt6 development libraries
- PostgreSQL 13+ (or Docker for containerized setup)
- OpenSSL for certificate generation

### Dependencies

- `wireguard-tools` (for WireGuard kernel module)
- `iptables` (for kill switch functionality on Linux)
- `build-essential`, `pkg-config` (Linux development tools)

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Shivam-1M/vpn.git
cd vpn
```

### 2. Set Up TLS Certificates

```bash
cd certs
# Generate CA certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.pem -config openssl.cnf

# Generate server certificate
openssl req -new -key server.key -out server.csr -config openssl.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365 -sha256
```

### 3. Set Up Database

```bash
cd vpn_control_plane
docker-compose up -d
```

### 4. Build Components

#### Control Plane (Go)

```bash
cd vpn_control_plane
go mod tidy
go build -o vpn_control_plane main.go
```

#### Data Plane (Rust)

```bash
cd vpn_data_plane
cargo build --release
```

#### Client Core (Rust)

```bash
cd vpn_client_core
cargo build --release
```

#### Desktop Client (C++)

```bash
cd vpn_desktop_client
mkdir build && cd build
cmake ..
make
```

### 5. Environment Variables

Create environment files or set variables:

For control plane:

```bash
export JWT_SECRET_KEY="your-secret-key-here"
export WG_PUBLIC_KEY="base64-encoded-server-public-key"
```

For data plane:

```bash
export WG_PRIVATE_KEY="base64-encoded-server-private-key"
```

## Usage

### Starting the Services

1. **Start Database**:

   ```bash
   cd vpn_control_plane
   docker-compose up -d
   ```

2. **Start Data Plane**:

   ```bash
   cd vpn_data_plane
   ./target/release/vpn_data_plane
   ```

3. **Start Control Plane**:

   ```bash
   cd vpn_control_plane
   ./vpn_control_plane
   ```

### Using the Desktop Client

1. **Launch the Application**:

   ```bash
   cd vpn_desktop_client/build
   ./VpnDesktopClient
   ```

2. **Register/Login**:

   - Enter your email and password
   - Register a new account or login to existing one

3. **Device Registration**:

   - If first time, register your device
   - Keys are encrypted and stored locally

4. **Connect to VPN**:

   - Click "Connect" to establish VPN connection
   - Kill switch will be enabled automatically
   - Monitor connection status

### API Usage

The control plane provides a REST API:

- `POST /register` - Register new user
- `POST /login` - User login
- `POST /devices` - Register device
- `GET /config` - Get VPN configuration
- `DELETE /devices/remove` - Remove device

Example login request:

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}'
```

## Development

### Building for Development

```bash
# Build all Rust components
cargo build

# Build Go component
go build

# Build Qt client
cmake --build build
```

### Testing

Currently, the project is in active development. Run individual component tests:

```bash
# Rust components
cargo test

# Go component
go test
```

### Code Generation

Regenerate gRPC code when modifying `vpn.proto`:

```bash
# For Go
protoc --go_out=. --go-grpc_out=. vpn/vpn.proto

# For Rust
cargo build  # Uses build.rs for code generation
```

## Current State

This project is currently in **development** (dev branch). Key features are implemented and functional:

- ✅ User authentication and device management
- ✅ WireGuard peer management via gRPC
- ✅ IP address allocation
- ✅ TLS-secured communication
- ✅ Desktop client with GUI
- ✅ Kill switch protection
- ✅ Automatic reconnection

**Known Limitations/Areas for Improvement**:

- Limited error handling in some edge cases
- No comprehensive test suite
- Database migrations not fully automated
- No CI/CD pipeline
- Documentation could be expanded

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`). We follow a Feature Branch Workflow.
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Considerations

- All gRPC communication is TLS-encrypted
- JWT tokens for API authentication
- WireGuard provides end-to-end encryption
- Kill switch prevents IP leaks
- Private keys are encrypted locally
- Certificate-based authentication for services

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Troubleshooting

### Common Issues

1. **Database Connection Failed**

   - Ensure PostgreSQL is running via Docker
   - Check connection string in control plane

2. **gRPC Connection Failed**

   - Verify data plane is running on port 50051
   - Check TLS certificates are valid

3. **VPN Connection Failed**

   - Ensure WireGuard kernel module is loaded
   - Check firewall rules for UDP port 51820

4. **Qt Client Build Issues**

   - Install Qt6 development packages
   - Ensure CMake can find Qt libraries

### Logs

- Control plane: Check stdout for Go logs
- Data plane: Uses env_logger, check console output
- Desktop client: Qt logging to console

For more detailed issues, check the respective component's source code and error messages.
