// Example: HiSLIP locking mechanism
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

	// Acquire exclusive lock with 5 second timeout
	fmt.Println("Acquiring lock...")
	if err := client.Lock(ctx, 5*time.Second); err != nil {
		log.Fatalf("Lock failed: %v", err)
	}
	fmt.Println("Lock acquired!")

	// Perform operations while holding lock
	idn, err := client.Query("*IDN?")
	if err != nil {
		log.Printf("Query failed: %v", err)
	} else {
		fmt.Printf("IDN: %s\n", idn)
	}

	// Simulate some work
	time.Sleep(2 * time.Second)

	// Release lock
	fmt.Println("Releasing lock...")
	if err := client.Unlock(ctx); err != nil {
		log.Fatalf("Unlock failed: %v", err)
	}
	fmt.Println("Lock released!")
}
