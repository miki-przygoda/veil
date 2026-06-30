// Package residents spawns synthetic inhabitants of the world. Each emits
// plausible background traffic on its own cadence so the environment looks alive
// from the inside — the "matrix" effect. Residents are the cheap, safe way to
// get believable activity without exposing real services or real people.
package residents

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/miki-przygoda/veil/internal/events"
)

// Resident is one synthetic inhabitant. It emits traffic until ctx is cancelled.
type Resident struct {
	Name     string
	Interval time.Duration
}

func (r *Resident) run(ctx context.Context, bus *events.Bus) {
	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()

	actions := []string{"GET /feed", "POST /login", "resolve dns", "fetch update", "send mail"}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e := events.New(events.KindTraffic, r.Name, actions[rand.Intn(len(actions))])
			e.Protocol = "http"
			e.Detail = fmt.Sprintf("session-%d", rand.Intn(9000)+1000)
			bus.Publish(e)
		}
	}
}

// Population manages a set of residents.
type Population struct {
	Size int
}

// Run spawns the residents and blocks until ctx is cancelled.
func (p *Population) Run(ctx context.Context, bus *events.Bus) {
	for i := 0; i < p.Size; i++ {
		r := &Resident{
			Name:     fmt.Sprintf("resident-%02d", i+1),
			Interval: time.Duration(2+rand.Intn(4)) * time.Second,
		}
		go r.run(ctx, bus)
	}
	<-ctx.Done()
}
