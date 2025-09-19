package main

import (
	"context"
	"encoding/json"
	"fmt" // ADD THIS
	"log"
	"net/http"
	"strings"
	"sync" // ADD THIS
	"time"

	pb "vpn_control_plane/vpn" // Import our generated protobuf package

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

	for {
		if i.nextHostID > i.maxHostID {
			return "", fmt.Errorf("no more available IPs in the pool")
		}
		ip := fmt.Sprintf("10.10.10.%d/32", i.nextHostID)
		if !i.assignedIPs[ip] {
			i.assignedIPs[ip] = true
			i.nextHostID++
			return ip, nil
		}
		i.nextHostID++
	}
}

// --- Database Models ---

// User represents a user account in the system.
type User struct {
	gorm.Model
	Email    string `gorm:"uniqueIndex;not null"`
	Password string `gorm:"not null"`
	Devices  []Device
}

// Device represents a user's device, identified by its WireGuard public key.
type Device struct {
	gorm.Model
	PublicKey string `gorm:"uniqueIndex;not null"`
	UserID    uint
}

// --- API Request/Response Structs ---

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type DeviceRequest struct {
	PublicKey string `json:"public_key"`
}

type VpnConfigResponse struct {
	ClientPrivateKey string `json:"client_private_key"`
	ClientIp         string `json:"client_ip"`
	ServerPublicKey  string `json:"server_public_key"`
	ServerEndpoint   string `json:"server_endpoint"`
}

// --- Global Variables ---

var db *gorm.DB
var vpnClient pb.VpnManagerClient // gRPC client
var ipam *Ipam                    // ADD THIS

// IMPORTANT: In a real production app, use a secure, randomly generated key from a config file or env var.
var jwtKey = []byte("my_secret_key")

// --- Main Application ---

func main() {
	// Initialize IPAM
	// We'll reserve IPs from 10.10.10.2 to 10.10.10.254
	ipam = NewIpam("10.10.10.0/24", 2, 254) // ADD THIS

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

	// --- gRPC Client Connection ---
	// Connect to the Rust Data Plane's gRPC server.
	// NOTE: This will fail until the Rust server is running its gRPC service.
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Did not connect to gRPC server: %v", err)
	}
	// We will defer closing the connection until the application exits.
	// In a real-world scenario with retries, this logic would be more robust.
	// defer conn.Close()
	vpnClient = pb.NewVpnManagerClient(conn)
	log.Println("gRPC client connected to data plane.")

	// --- API Routes ---
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	// We wrap the addDeviceHandler with our JWT middleware to protect it.
	http.Handle("/devices", jwtMiddleware(http.HandlerFunc(addDeviceHandler)))
	http.Handle("/config", jwtMiddleware(http.HandlerFunc(getConfigHandler)))

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

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)
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

	// --- JWT Token Generation ---
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &jwt.RegisteredClaims{
		Subject:   user.Email,
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Server error, unable to generate token.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
	log.Printf("User logged in: %s", creds.Email)
}

func addDeviceHandler(w http.ResponseWriter, r *http.Request) {
	// The user's email is added to the request context by the middleware.
	email := r.Context().Value(contextKey("userEmail")).(string)

	var devReq DeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&devReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Find the user in the database
	var user User
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Save the new device to the database
	device := Device{PublicKey: devReq.PublicKey, UserID: user.ID}
	if err := db.Create(&device).Error; err != nil {
		http.Error(w, "Public key may already exist", http.StatusConflict)
		return
	}

	// --- Make the gRPC call to the Rust Data Plane ---
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	res, err := vpnClient.AddPeer(ctx, &pb.PeerRequest{PublicKey: devReq.PublicKey})
	if err != nil {
		log.Printf("gRPC call to AddPeer failed: %v", err)
		// Note: In a real app, we might want to roll back the database change here.
		http.Error(w, "Could not configure peer on data plane", http.StatusInternalServerError)
		return
	}

	log.Printf("gRPC AddPeer response: %v", res.Message)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Device added successfully",
		"status":  res.Message,
	})
	log.Printf("Added new device for user %s with public key %s", email, devReq.PublicKey)
}

func getConfigHandler(w http.ResponseWriter, r *http.Request) {
	// The user's email is added to the request context by the middleware.
	email := r.Context().Value(contextKey("userEmail")).(string)
	log.Printf("Config requested for user: %s", email)

	// Get the next available IP from our IPAM
	clientIP, err := ipam.GetNextIP()
	if err != nil {
		log.Printf("IPAM error: %v", err)
		http.Error(w, "Could not assign IP address", http.StatusInternalServerError)
		return
	}
	log.Printf("Assigned IP %s to user %s", clientIP, email)

	// In a real application, you would also generate a unique private key
	// for the client here. For now, we'll keep the placeholder.
	config := VpnConfigResponse{
		ClientPrivateKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", // Placeholder
		ClientIp:         clientIP,
		ServerPublicKey:  "j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8=", // The public key from your Rust server
		ServerEndpoint:   "127.0.0.1:51820",                              // Your server's public IP
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
