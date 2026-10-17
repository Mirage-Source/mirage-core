package shell

import "embed"

// rootfs holds stock Ubuntu 22.04 files copied verbatim from the
// reference container (ubuntu:22.04 + openssh-server 8.9p1), so their
// content and size are the real ones. Changes from the copies:
// os-release says 22.04.3 (the version this sensor claims), passwd drops
// the container's own test user and adds ubuntu (uid 1000, as on EC2),
// and .bashrc ends with a ~/.local/bin PATH line.
//
//go:embed all:rootfs
var rootfs embed.FS

func rootFile(name string) string {
	b, err := rootfs.ReadFile("rootfs/" + name)
	if err != nil {
		panic(err)
	}
	return string(b)
}
