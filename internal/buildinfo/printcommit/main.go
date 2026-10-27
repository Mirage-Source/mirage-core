// Command printcommit prints the linked-in build commit. It exists so
// buildinfo's tests can prove the -X flag the Dockerfiles use really lands.
package main

import (
	"fmt"

	"github.com/mirage-source/mirage-core/internal/buildinfo"
)

func main() { fmt.Println(buildinfo.Commit) }
