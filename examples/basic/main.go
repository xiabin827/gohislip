// Example: Basic HiSLIP client usage
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/xiabin827/gohislip"
)

func main() {
	// Parse command line arguments
	addr := flag.String("addr", "localhost:4880", "HiSLIP server address")
	subAddr := flag.String("sub", "hislip0", "HiSLIP sub-address")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	// Create client configuration
	config := &gohislip.ClientConfig{
		SubAddress: *subAddr,
		VendorID:   0,
		Timeout:    10 * time.Second,
	}

	if *debug {
		config.Logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	}

	// Connect to server
	ctx := context.Background()
	client, err := gohislip.Dial(ctx, *addr, config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	fmt.Printf("Connected to %s\n", *addr)
	fmt.Printf("Session ID: %d\n", client.Session().SessionID())

	// Query instrument identification
	idn, err := client.Query("*IDN?")
	if err != nil {
		log.Fatalf("Query *IDN? failed: %v", err)
	}
	fmt.Printf("Instrument ID: %s\n", idn)

	// Reset instrument
	if err := client.Write("*RST"); err != nil {
		log.Fatalf("Write *RST failed: %v", err)
	}
	fmt.Println("Instrument reset")

	// Query status byte
	stb, err := client.Status(ctx)
	if err != nil {
		log.Fatalf("Status query failed: %v", err)
	}
	fmt.Printf("Status byte: 0x%02X\n", stb)

	// Example: Query with explicit timeout
	opc, err := client.Query("*OPC?")
	if err != nil {
		log.Fatalf("Query *OPC? failed: %v", err)
	}
	fmt.Printf("OPC: %s\n", opc)

	fmt.Println("Done!")
}
