package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "vpn_control_plane/vpn" // Import our generated protobuf package

	"crypto/rand"
	"crypto/tls"
	"crypto/x509"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// --- IPAM ---
// A simple IP Address Manager
type Ipam struct {
	mu          sync.Mutex
	network     string
	nextHostID  int
	maxHostID   int
	assignedIPs map[string]bool
}

// NewIpam creates a new IPAM instance.
func NewIpam(network string, startHostID int, endHostID int) *Ipam {
	return &Ipam{
		network:     network,
		nextHostID:  startHostID,
		maxHostID:   endHostID,
		assignedIPs: make(map[string]bool),
	}
}

// GetNextIP returns the next available IP address.
func (i *Ipam) GetNextIP() (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	start := i.nextHostID
	for {
		// Create IP with current host ID
		ip := fmt.Sprintf("10.10.10.%d/32", i.nextHostID)

		// If the IP is not already assigned, use it
		if !i.assignedIPs[ip] {
			i.assignedIPs[ip] = true
			i.nextHostID++
			return ip, nil
		}

		// Otherwise, increment and try the next one
		i.nextHostID++
		if i.nextHostID > i.maxHostID {
			i.nextHostID = 2 // Wrap around if we reach the end
		}
		if i.nextHostID == start {
			// If we've wrapped all the way around, the pool is full
			return "", fmt.Errorf("no more available IPs in the pool")
		}
	}
}

// --- Database Models ---

// User represents a user account in the system.
type User struct {
	gorm.Model
	Email              string `gorm:"uniqueIndex;not null"`
	Password           string `gorm:"not null"`
	RefreshToken       string `gorm:"uniqueIndex"`
	RefreshTokenExpiry time.Time
	Devices            []Device
}

// Device represents a user's device, identified by its WireGuard public key.
type Device struct {
	gorm.Model
	PublicKey string `gorm:"uniqueIndex;not null"`
	IPAddress string `gorm:"uniqueIndex;not null"`
	UserID    uint
}

// --- API Request/Response Structs ---

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type DeviceRequest struct {
	PublicKey string `json:"public_key"`
}

type VpnConfigResponse struct {
	ClientPrivateKey string `json:"client_private_key"`
	ClientIp         string `json:"client_ip"`
	DnsServer        string `json:"dns_server"` // ADD THIS
	ServerPublicKey  string `json:"server_public_key"`
	ServerEndpoint   string `json:"server_endpoint"`
}

// --- Global Variables ---

var db *gorm.DB
var vpnClient pb.VpnManagerClient // gRPC client
var ipam *Ipam
var jwtKey []byte
var serverPublicKey string

// --- Main Application ---

func main() {
	// Initialize IPAM
	// We'll reserve IPs from 10.10.10.2 to 10.10.10.254
	ipam = NewIpam("10.10.10.0/24", 2, 254)

	// Load JWT secret key from environment variable
	jwtSecret := os.Getenv("JWT_SECRET_KEY")
	if jwtSecret == "" {
		log.Fatal("FATAL: JWT_SECRET_KEY environment variable not set.")
	}
	jwtKey = []byte(jwtSecret)

	// Load Server Public Key from environment variable
	serverPublicKey = os.Getenv("WG_PUBLIC_KEY")
	if serverPublicKey == "" {
		log.Fatal("FATAL: WG_PUBLIC_KEY environment variable not set.")
	}

	// --- Database Connection ---
	var err error
	dsn := "host=localhost user=vpnuser password=vpnpassword dbname=vpn port=5432 sslmode=disable"
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	log.Println("Database connection established.")

	db.AutoMigrate(&User{}, &Device{})
	log.Println("Database schema migrated successfully.")

	var existingDevices []Device
	if err := db.Find(&existingDevices).Error; err == nil {
		highestHostID := 0
		for _, device := range existingDevices {
			// Mark the IP as assigned in our map
			ipam.assignedIPs[device.IPAddress] = true

			// Also, find the highest assigned IP to avoid collisions
			parts := strings.Split(strings.TrimSuffix(device.IPAddress, "/32"), ".")
			if len(parts) == 4 {
				hostID, _ := strconv.Atoi(parts[3])
				if hostID > highestHostID {
					highestHostID = hostID
				}
			}
		}
		// Set the next IP to be one higher than the highest found in the DB
		if highestHostID > 0 {
			ipam.nextHostID = highestHostID + 1
		}
		log.Printf("IPAM initialized. Found %d existing IPs. Next IP will start from host ID %d.", len(ipam.assignedIPs), ipam.nextHostID)
	}

	// --- gRPC Client Connection ---
	ca_cert, err := os.ReadFile("../certs/ca.pem")
	if err != nil {
		log.Fatalf("Could not read CA certificate: %v", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(ca_cert) {
		log.Fatal("Failed to append CA certificate")
	}

	// Note: For local testing, ServerName must match the CN in the server's cert ('localhost')
	tlsConfig := &tls.Config{
		ServerName: "localhost",
		RootCAs:    certPool,
	}

	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("Did not connect to gRPC server: %v", err)
	}

	vpnClient = pb.NewVpnManagerClient(conn)
	log.Println("Secure gRPC client connected to data plane.")

	// --- API Routes ---
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	// We wrap the addDeviceHandler with our JWT middleware to protect it.
	http.Handle("/devices", jwtMiddleware(http.HandlerFunc(addDeviceHandler)))
	http.Handle("/config", jwtMiddleware(http.HandlerFunc(getConfigHandler)))
	http.Handle("/devices/remove", jwtMiddleware(http.HandlerFunc(removeDeviceHandler)))
	http.HandleFunc("/refresh", refreshTokenHandler)

	log.Println("Starting VPN Control Plane server on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Could not start server: %s\n", err)
	}
}

// --- API Handlers ---

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var creds AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 12)
	if err != nil {
		http.Error(w, "Server error, unable to create your account.", http.StatusInternalServerError)
		return
	}

	user := User{Email: creds.Email, Password: string(hashedPassword)}
	result := db.Create(&user)
	if result.Error != nil {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User created successfully"))
	log.Printf("New user registered: %s", creds.Email)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var user User
	result := db.Where("email = ?", creds.Email).First(&user)
	if result.Error != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// 1. Generate Access Token (short-lived, e.g., 15 minutes)
	accessToken, err := createAccessToken(user.Email)
	if err != nil {
		http.Error(w, "Server error, unable to generate token.", http.StatusInternalServerError)
		return
	}

	// 2. Generate and store Refresh Token (long-lived, e.g., 7 days)
	refreshToken, err := createAndStoreRefreshToken(&user)
	if err != nil {
		http.Error(w, "Server error, unable to create refresh token.", http.StatusInternalServerError)
		return
	}

	// 3. Send both tokens to the client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
	log.Printf("User logged in: %s", creds.Email)
}

func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var user User
	result := db.Where("refresh_token = ?", body.RefreshToken).First(&user)
	if result.Error != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Check if the refresh token has expired
	if user.RefreshTokenExpiry.Before(time.Now()) {
		http.Error(w, "Refresh token expired", http.StatusUnauthorized)
		return
	}

	// Generate a new access token
	newAccessToken, err := createAccessToken(user.Email)
	if err != nil {
		http.Error(w, "Server error, unable to generate new token.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"access_token": newAccessToken,
	})
}

func createAccessToken(email string) (string, error) {
	// Increased expiration to 15 minutes
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &jwt.RegisteredClaims{
		Subject:   email,
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func createAndStoreRefreshToken(user *User) (string, error) {
	// Generate a secure random string for the refresh token
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	refreshToken := hex.EncodeToString(b)

	// Set a long expiry, for example, 7 days
	expiryTime := time.Now().Add(7 * 24 * time.Hour)

	user.RefreshToken = refreshToken
	user.RefreshTokenExpiry = expiryTime
	if err := db.Save(user).Error; err != nil {
		return "", err
	}

	return refreshToken, nil
}

func addDeviceHandler(w http.ResponseWriter, r *http.Request) {
	email := r.Context().Value(contextKey("userEmail")).(string)

	var devReq DeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&devReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 1. Get a new IP from the IPAM for the new device
	assignedIP, err := ipam.GetNextIP()
	if err != nil {
		log.Printf("IPAM error: %v", err)
		http.Error(w, "Could not assign IP address", http.StatusInternalServerError)
		return
	}

	// 2. Save the new device with its IP to the database
	device := Device{PublicKey: devReq.PublicKey, IPAddress: assignedIP, UserID: user.ID}
	if err := db.Create(&device).Error; err != nil {
		http.Error(w, "Public key or IP may already exist", http.StatusConflict)
		// Note: You would want to release the IP back to the pool here in a real app
		return
	}

	// 3. Make the gRPC call to the Rust Data Plane with the new IP
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// The gRPC struct `pb.PeerRequest` is now updated from the regenerated code
	res, err := vpnClient.AddPeer(ctx, &pb.PeerRequest{
		PublicKey: devReq.PublicKey,
		IpAddress: assignedIP, // Send the assigned IP
	})
	if err != nil {
		log.Printf("gRPC call to AddPeer failed: %v", err)
		// Note: Roll back the database change here in a real app.
		http.Error(w, "Could not configure peer on data plane", http.StatusInternalServerError)
		return
	}
	log.Printf("gRPC AddPeer response: %v", res.Message)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Device added successfully with IP " + assignedIP,
		"status":  res.Message,
	})
	log.Printf("Added new device for user %s with public key %s and IP %s", email, devReq.PublicKey, assignedIP)
}

func removeDeviceHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure this is a DELETE request
	if r.Method != http.MethodDelete {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	email := r.Context().Value(contextKey("userEmail")).(string)

	var devReq DeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&devReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 1. Find the user in the database
	var user User
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 2. Find the specific device to be deleted
	var device Device
	if err := db.Where("public_key = ? AND user_id = ?", devReq.PublicKey, user.ID).First(&device).Error; err != nil {
		http.Error(w, "Device not found for this user", http.StatusNotFound)
		return
	}

	// 3. Make the gRPC call to the Rust Data Plane to remove the peer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := vpnClient.RemovePeer(ctx, &pb.PeerRequest{PublicKey: devReq.PublicKey})
	if err != nil {
		// Log the gRPC error, but don't stop. We still want to remove the device
		// from our database. The data plane might be temporarily down.
		log.Printf("gRPC call to RemovePeer failed: %v. Continuing with DB removal.", err)
	}

	// 4. Delete the device from the database
	if err := db.Delete(&device).Error; err != nil {
		http.Error(w, "Failed to remove device from database", http.StatusInternalServerError)
		return
	}

	log.Printf("Removed device for user %s with public key %s", email, devReq.PublicKey)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Device removed successfully",
	})
}

func getConfigHandler(w http.ResponseWriter, r *http.Request) {
	email := r.Context().Value(contextKey("userEmail")).(string)
	log.Printf("Config requested for user: %s", email)

	// 1. Find the user
	var user User
	if err := db.Where("email = ?", email).Preload("Devices").First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 2. Find their most recently created device
	if len(user.Devices) == 0 {
		http.Error(w, "No registered devices found for this user", http.StatusNotFound)
		return
	}
	// For simplicity, we get the last device. A real app might let the user choose.
	latestDevice := user.Devices[len(user.Devices)-1]

	// 3. Return the config using the IP from the database
	config := VpnConfigResponse{
		ClientIp:        latestDevice.IPAddress,
		DnsServer:       "1.1.1.1",
		ServerPublicKey: serverPublicKey,
		ServerEndpoint:  "127.0.0.1:51820",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(config)
}

// --- Middleware ---

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &jwt.RegisteredClaims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add user email to context to pass to the handler using custom key type
		ctx := context.WithValue(r.Context(), contextKey("userEmail"), claims.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
