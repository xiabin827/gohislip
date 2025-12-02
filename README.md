# gohislip

Go implementation of the HiSLIP 2.0 protocol (IVI-6.1) for controlling test and measurement instruments over TCP/IP.

## Features

- **Full HiSLIP 2.0 Support**: Implements the complete IVI-6.1 HiSLIP specification
- **Dual Channel Architecture**: Synchronous and asynchronous TCP connections
- **Both Modes**: Synchronized and overlapped operation modes
- **Secure Connection**: TLS/SASL support for encrypted communication
- **Locking**: Exclusive lock acquisition and release
- **Device Clear**: Full device clear implementation
- **SRQ Handling**: Service Request callback support
- **Status Query**: Read instrument status byte

## Installation

```bash
go get github.com/xiabin827/gohislip
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/xiabin827/gohislip"
)

func main() {
    // Create client with configuration
    config := &gohislip.ClientConfig{
        SubAddress: "hislip0",
        Timeout:    10 * time.Second,
    }

    // Connect to instrument
    ctx := context.Background()
    client, err := gohislip.Dial(ctx, "192.168.1.100:4880", config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Query instrument ID
    idn, err := client.Query("*IDN?")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Instrument:", idn)
}
```

## API Reference

### Client Creation

```go
// Create with default config
client, err := gohislip.Dial(ctx, "address:4880", nil)

// Create with custom config
config := &gohislip.ClientConfig{
    SubAddress:        "hislip0",
    VendorID:          0,
    Timeout:           30 * time.Second,
    TLSConfig:         nil,  // or *tls.Config for secure connection
    UseOverlappedMode: false,
    Logger:            log.Default(), // for debug output
}
client, err := gohislip.Dial(ctx, "address:4880", config)
```

### Basic Operations

```go
// Send command (no response expected)
err := client.Write("*RST")

// Query (send command and read response)
response, err := client.Query("*IDN?")

// Send raw bytes
err := client.WriteBytes([]byte{...})

// Read raw response
data, err := client.Read()
data, err := client.ReadWithTimeout(5 * time.Second)

// Trigger
err := client.Trigger()
```

### Locking

```go
// Acquire exclusive lock with timeout
err := client.Lock(ctx, 5*time.Second)

// Release lock
err := client.Unlock(ctx)
```

### Status and Device Clear

```go
// Query status byte
stb, err := client.Status(ctx)

// Device clear (reset buffers)
err := client.DeviceClear(ctx)
```

### Service Request (SRQ)

```go
// Set callback for SRQ notifications
client.SetSRQCallback(func(stb byte) {
    fmt.Printf("SRQ received: 0x%02X\n", stb)
})
```

### TLS/Secure Connection

```go
// Create TLS config
tlsConfig := gohislip.NewTLSConfig("instrument.example.com")

// Or with CA certificate
tlsConfig, err := gohislip.NewTLSConfigWithCA("instrument.example.com", "/path/to/ca.crt")

// Or with client certificate
tlsConfig, err := gohislip.NewTLSConfigWithCert("instrument.example.com", "client.crt", "client.key")

// Use in client config
config := &gohislip.ClientConfig{
    TLSConfig: tlsConfig,
}

// Or upgrade existing connection
err := client.StartTLS(ctx)
```

## Protocol Details

### Message Format

All HiSLIP messages consist of a 16-byte header followed by optional payload:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | Prologue "HS" |
| 2 | 1 | Message Type |
| 3 | 1 | Control Code |
| 4 | 4 | Message Parameter |
| 8 | 8 | Payload Length |

### Connection Architecture

```
┌────────────────────────────────────────────────────────────┐
│                        Client                               │
├─────────────────────────┬──────────────────────────────────┤
│   Synchronous Channel   │      Asynchronous Channel        │
│   - Data/DataEnd        │      - AsyncLock                 │
│   - Trigger             │      - AsyncStatusQuery          │
│   - DeviceClearComplete │      - AsyncDeviceClear          │
│                         │      - AsyncServiceRequest       │
└────────────┬────────────┴──────────────────┬───────────────┘
             │                               │
             └───────────── TCP ─────────────┘
                           │
                    ┌──────┴──────┐
                    │  Instrument │
                    └─────────────┘
```

### Operation Modes

- **Synchronized Mode** (default): One query at a time, simpler error handling
- **Overlapped Mode**: Multiple concurrent queries, responses matched by MessageID

## Examples

See the [examples](./examples) directory:

- `basic/` - Simple query and write operations
- `lock/` - Lock acquisition and release
- `srq/` - Service Request handling

## Testing

```bash
go test ./...
```

## Compliance

This implementation follows the [IVI-6.1 HiSLIP Specification](https://www.ivifoundation.org/specifications/).

## License

MIT License - see [LICENSE](LICENSE) file.
