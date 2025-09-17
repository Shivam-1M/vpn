#ifndef VPN_CLIENT_CORE_H
#define VPN_CLIENT_CORE_H

#include <stdint.h>

// This is the C++ header file for our Rust FFI library.
// It declares the functions that are exposed from the Rust code, allowing
// us to call them from C++.

#ifdef __cplusplus
extern "C" {
#endif

// Define an opaque pointer for the VpnClient struct. C++ doesn't need to know
// its internal layout, only that it's a pointer.
typedef struct VpnClient VpnClient;

// Declare the functions from the Rust library.
VpnClient* vpn_client_create();
int32_t vpn_client_connect(VpnClient* client, const char* private_key, const char* client_ip, const char* server_pubkey, const char* server_endpoint);
int32_t vpn_client_disconnect(VpnClient* client);
void vpn_client_destroy(VpnClient* client);

#ifdef __cplusplus
}
#endif

#endif // VPN_CLIENT_CORE_H
