// Command veil-agent is a placeholder. The subject is driven from the HOST side
// (brain outside): veild's subject broker execs commands inside the box via the
// sandbox Execer seam and records the transcript. There is deliberately no
// in-box agent that phones home — that would require egress and put subject logic
// inside the threat model. This stub remains only as a build target; see
// internal/subject and cmd/veild's -subject flag.
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
