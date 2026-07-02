// Command veil-agent is the guest-side companion that runs *inside* the
// contained world. For now it is a placeholder that heartbeats; later it will
// broker the subject's tool calls and report from within the box.
//
// It exists already so the two-binary split (host daemon vs guest agent) is
// real from day one — which is what justifies the cmd/ layout.
package main

import (
	"log"
	"time"
)

func main() {
	log.SetPrefix("veil-agent ")
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Println("starting inside the world")

	for {
		time.Sleep(30 * time.Second)
		log.Println("heartbeat")
	}
}
