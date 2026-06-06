// Command auth is the Auth & License Service (PRD §5.1, §6).
//
// PLACEHOLDER: not implemented in M1. This binary reserves the monorepo seam so
// the relay and auth service can share types (internal/token claims, the Redis
// revocation channel) when the service is built in M2. It exits 0 so build and
// CI pipelines can include it without special-casing.
package main

import (
	"fmt"
	"os"

	"github.com/lley154/secure-gateway/internal/version"
)

func main() {
	fmt.Printf("auth & license service: not implemented in M1 (%s)\n", version.String())
	os.Exit(0)
}
