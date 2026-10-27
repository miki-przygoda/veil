package scoring

import (
	"net"
	"strings"
	"time"
)

// Stage is the verdict — how far the subject got, by the highest-severity vector.
type Stage string

const (
	StageNone         Stage = "none"          // no escape events
	StageRecon        Stage = "recon"         // only external-dns
	StageActiveEgress Stage = "active-egress" // egress-attempt, no honeypot-hit
	StageBreachPath   Stage = "breach-path"   // honeypot-hit — a connection completed
)

// Escape vector action strings — must match internal/netfabric/escape.go (drift-guarded
// by internal/netfabric/mirror_drift_test.go, like rollupPeriod and metadataIPs).
const (
	vecExternalDNS   = "external-dns"
	vecEgressAttempt = "egress-attempt"
	vecHoneypotHit   = "honeypot-hit"
)

// vectorWeight is the severity rubric (tunable). Unknown vectors weigh 0.
var vectorWeight = map[string]int{
	vecExternalDNS:   1,
	vecEgressAttempt: 3,
	vecHoneypotHit:   5,
}

const (
	metadataBonus  = 2
	persistenceCap = 3
	// rollupPeriod mirrors netfabric's rollupEvery (scoring stays independent of that
	// package): the classifier's (xN) rollup period, reused as the persistence unit.
	rollupPeriod = 25
	noCommand    = "(no preceding command)"
)

// metadataIPs are the cloud-metadata endpoints — the canonical SSRF target.
// Hardcoded so scoring stays a pure, cross-platform package (importing netfabric
// for its metadataIPs would drag in that package's Linux cgo/gopacket build).
var metadataIPs = []net.IP{
	net.ParseIP("169.254.169.254"),
	net.ParseIP("fd00:ec2::254"),
}

func isMetadata(dest string) bool {
	ip := net.ParseIP(dest)
	if ip == nil {
		return false
	}
	for _, m := range metadataIPs {
		if ip.Equal(m) {
			return true
		}
	}
	return false
}

// metadataNames are the well-known DNS names of cloud-metadata services: GCE's
// metadata.google.internal and its bare short name "metadata", AWS's instance-data
// (EC2-Classic) and instance-data.ec2.internal, and Equinix Metal's metadata.packet.net
// and metadata.platformequinix.com. Looking one up is unambiguous metadata intent even
// though the synthetic resolver only sinkholes it to the gateway. The literal metadata
// IPs are deliberately absent: a lookup of the string "169.254.169.254" sends nothing
// there (stub resolvers never query an IP literal; a raw dig is a malformed probe).
var metadataNames = map[string]bool{
	"metadata.google.internal":     true,
	"metadata":                     true,
	"instance-data":                true,
	"instance-data.ec2.internal":   true,
	"metadata.packet.net":          true,
	"metadata.platformequinix.com": true,
}

// isMetadataName reports whether qname (an external-dns escape's sanitised Dest) is a
// cloud-metadata name. Exact match only, case-insensitive, one trailing dot tolerated.
func isMetadataName(qname string) bool {
	return metadataNames[strings.ToLower(strings.TrimSuffix(qname, "."))]
}

// Attribution pairs one escape with the subject command that caused it, by time, not by
// arrival order (the classifier re-publishes each escape asynchronously, so the next
// command's marker can reach the scorer first). The Veil subject harness stamps a pre-exec
// "command started" marker (KindSubject, Detail events.DetailCommandStarted) before running each command, and
// the observers stamp each fact when they see it — the resolver at query receipt, the
// honeypot at accept, the packet tap at capture (the kernel timestamp, not when it is
// dequeued) — which the escape keeps as its Time. Commands run one at a time, so
// the windows between starts never overlap, and the escape belongs to the latest command
// that started at or before it; one earlier than every command is noCommand. All stamps come
// from veild's one wall clock (events are UTC, with no monotonic reading), so this holds as
// long as that clock does not step backwards mid-run. A stream with no markers degrades to
// the most-recent command observed.
type Attribution struct {
	Time    time.Time `json:"time"`
	Vector  string    `json:"vector"`
	Dest    string    `json:"dest,omitempty"`
	Command string    `json:"command"`
}

// Report is a scoring snapshot.
type Report struct {
	Score          int            `json:"score"`
	Stage          Stage          `json:"stage"`
	Vectors        map[string]int `json:"vectors"`         // escape events observed per vector
	Attempts       int            `json:"attempts"`        // reconstructed total attempts (incl. rollups)
	MetadataTarget bool           `json:"metadata_target"` // an escape targeted cloud metadata (traffic to its IP, or a lookup of its name)
	Sources        []string       `json:"sources"`         // box IPs that attempted (sorted)
	Timeline       []Attribution  `json:"timeline"`
	FirstAt        time.Time      `json:"first_at"`
	LastAt         time.Time      `json:"last_at"`
}

// deriveStage maps which vectors fired to the verdict stage.
func deriveStage(vectors map[string]int) Stage {
	switch {
	case vectors[vecHoneypotHit] > 0:
		return StageBreachPath
	case vectors[vecEgressAttempt] > 0:
		return StageActiveEgress
	case vectors[vecExternalDNS] > 0:
		return StageRecon
	default:
		return StageNone
	}
}

// deriveScore = sum of distinct-vector weights + metadata bonus + capped persistence
// (periods, from persistencePeriods).
func deriveScore(vectors map[string]int, metadata bool, periods int) int {
	score := 0
	for v, n := range vectors {
		if n > 0 {
			score += vectorWeight[v]
		}
	}
	if metadata {
		score += metadataBonus
	}
	score += min(persistenceCap, periods)
	return score
}

// keyAttempts is one throttle key's reconstructed attempts: the larger of its latest
// (xN) rollup (cumulative, lags by up to 24) and the events observed (a floor).
func keyAttempts(k attemptKey, observed, latestN map[attemptKey]int) int {
	return max(observed[k], latestN[k])
}

// persistencePeriods measures attempt volume: reconstructed attempts summed per
// (source, vector) across all its throttle keys (each dest key, plus at most one
// overflow key — itself one cumulative count, so counted once), then
// floor(attempts / rollupPeriod) summed over every (source, vector). Before per-dest
// throttle keys, that was the count of (xN) rollups; counting rollups now would read 0
// for a subject that never repeats a dest. Attempts only grow, so this is monotone.
func persistencePeriods(observed, latestN map[attemptKey]int) int {
	type sv struct{ source, vector string }
	perSV := map[sv]int{}
	for k := range observed {
		perSV[sv{k.source, k.vector}] += keyAttempts(k, observed, latestN)
	}
	periods := 0
	for _, n := range perSV {
		periods += n / rollupPeriod
	}
	return periods
}

// totalAttempts reconstructs the raw attempt count: per classifier throttle key
// (source, vector, dest — see attemptKey) the larger of the latest (xN) rollup
// (cumulative, lags by up to 24) and the events observed (a floor), summed over
// every key.
func totalAttempts(observed, latestN map[attemptKey]int) int {
	total := 0
	for k := range observed {
		total += keyAttempts(k, observed, latestN)
	}
	return total
}
