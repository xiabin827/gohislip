// Example: Service Request (SRQ) handling
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xiabin827/gohislip"
)

func main() {
	addr := flag.String("addr", "localhost:4880", "HiSLIP server address")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	config := &gohislip.ClientConfig{
		SubAddress: "hislip0",
		Timeout:    10 * time.Second,
	}
	if *debug {
		config.Logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	}

	ctx := context.Background()
	client, err := gohislip.Dial(ctx, *addr, config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	fmt.Println("Connected!")

	// Set up SRQ callback
	client.SetSRQCallback(func(stb byte) {
		fmt.Printf(">>> SRQ received! Status byte: 0x%02X\n", stb)

		// Check status bits
		if stb&0x40 != 0 { // RQS/MSS bit
			fmt.Println("    Request Service bit set")
		}
		if stb&0x20 != 0 { // ESB bit
			fmt.Println("    Event Status bit set")
		}
		if stb&0x10 != 0 { // MAV bit
			fmt.Println("    Message Available bit set")
		}

		// Could query *ESR? here to get more details
	})

	// Enable SRQ for operation complete
	fmt.Println("Configuring SRQ for OPC...")
	if err := client.Write("*ESE 1"); err != nil { // Enable OPC in ESR
		log.Printf("Write *ESE failed: %v", err)
	}
	if err := client.Write("*SRE 32"); err != nil { // Enable ESB in SRQ
		log.Printf("Write *SRE failed: %v", err)
	}

	// Trigger a long operation
	fmt.Println("Starting operation...")
	if err := client.Write("*OPC"); err != nil {
		log.Printf("Write *OPC failed: %v", err)
	}

	// Wait for interrupt
	fmt.Println("Waiting for SRQ... (Press Ctrl+C to exit)")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nExiting...")
}
