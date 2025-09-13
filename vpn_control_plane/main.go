package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

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

// --- Main Application ---

var db *gorm.DB

func main() {
	// --- Database Connection ---
	var err error
	dsn := "host=localhost user=vpnuser password=vpnpassword dbname=vpn port=5432 sslmode=disable"
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	} else {
		log.Println("Database connection established.")
	}

	// Auto-migrate the schema to create tables for our models.
	err = db.AutoMigrate(&User{}, &Device{})
	if err != nil {
		log.Fatal("Failed to migrate database schema:", err)
	} else {
		log.Println("Database schema migrated successfully.")
	}

	// Simple HTTP server to confirm the control plane is running.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "VPN Control Plane is running and connected to the database!")
	})

	log.Println("Starting VPN Control Plane server on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Could not start server: %s\n", err)
	}
}

// Helper function to get environment variables with a default value
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
