package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	// Simple HTTP server to confirm the control plane is running.
	// We will replace this with our actual API later.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "VPN Control Plane is running!")
	})

	log.Println("Starting VPN Control Plane server on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Could not start server: %s\n", err)
	}
}
