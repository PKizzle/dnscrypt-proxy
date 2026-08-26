package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
)

// instanceID names this process among the instances that share a dashboard.
//
// The host name alone would not do: it is shared by instances running side by
// side on one machine, and an address is not an identity either -- one instance
// is reachable at every address it listens on, and a name resolving to both an
// A and a AAAA record hands back two of them. The random half is what keeps two
// instances distinct, and what stops a restarted instance from being mistaken
// for the one it replaced.
var instanceID = newInstanceID()

func newInstanceID() string {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		// Only the distinguishing half is lost, and the host name still
		// separates instances on different machines: better than no identity,
		// which would make every instance look like every other.
		return hostnameOrUnknown()
	}
	return hostnameOrUnknown() + "-" + hex.EncodeToString(suffix[:])
}

func hostnameOrUnknown() string {
	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}
	return "unknown"
}
