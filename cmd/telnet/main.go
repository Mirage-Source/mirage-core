package main

import (
	"github.com/mirage-source/mirage-core/internal/server"
)

func main() {
	server.StartTelnet(":2323")
}
