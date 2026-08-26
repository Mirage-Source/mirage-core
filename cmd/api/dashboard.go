package main

import "embed"

// dashboardFS embeds the validity dashboard's static assets at compile
// time, so serving it needs no separate build step or runtime file
// dependency -- the existing `go build ./cmd/api` already picks it up.
//
//go:embed dashboard/index.html
var dashboardFS embed.FS
