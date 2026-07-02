//go:build !linux

package netfabric

// openBridge is unsupported off Linux; veild falls back to StubTap.
func openBridge(string) (packetSource, error) { return nil, ErrCaptureUnsupported }
