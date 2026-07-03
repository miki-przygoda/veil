package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	log.SetPrefix("veil-resident ")
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		log.Fatalf("run: %v", err)
	}
	log.Println("shutdown complete")
}

// run binds every configured service listener up front (a bind failure is fatal),
// starts each service + the client loop, and blocks until ctx is cancelled, then
// waits for a clean shutdown.
func run(ctx context.Context, cfg config) error {
	services, err := buildServices(cfg.services, cfg.hostname)
	if err != nil {
		return err
	}
	// Bind all listeners first so a failure doesn't leave half the world up.
	lns := make([]net.Listener, 0, len(services))
	for _, s := range services {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
		if err != nil {
			for _, l := range lns {
				_ = l.Close()
			}
			return fmt.Errorf("listen :%d: %w", s.port, err)
		}
		lns = append(lns, ln)
	}

	var wg sync.WaitGroup
	for i, s := range services {
		wg.Add(1)
		go func(s svc, ln net.Listener) {
			defer wg.Done()
			log.Printf("serving %d", s.port)
			if err := s.run(ctx, ln); err != nil {
				log.Printf("service :%d: %v", s.port, err)
			}
		}(s, lns[i])
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = newClient(cfg.targets, cfg.resolver, cfg.interval, cfg.seed).runClient(ctx)
	}()

	<-ctx.Done()
	wg.Wait()
	return nil
}
