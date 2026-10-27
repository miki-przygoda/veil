package scoring

import "net"

// Read-only views of the values scoring mirrors from internal/netfabric, for the drift
// guard in internal/netfabric/mirror_drift_test.go (netfabric's tests may import scoring;
// scoring must not import netfabric). Nothing reads them at runtime.
const (
	MirrorMaxThrottleDest     = maxThrottleDest
	MirrorThrottleOverflowTag = throttleOverflowTag
	MirrorRollupPeriod        = rollupPeriod
)

// MirrorVectors returns the escape vector names scoring grades.
func MirrorVectors() []string {
	return []string{vecExternalDNS, vecEgressAttempt, vecHoneypotHit}
}

// MirrorMetadataIPs returns a copy of scoring's cloud-metadata IPs.
func MirrorMetadataIPs() []net.IP {
	out := make([]net.IP, len(metadataIPs))
	copy(out, metadataIPs)
	return out
}
