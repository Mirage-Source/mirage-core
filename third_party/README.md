# third_party

## golang.org/x/crypto (v0.55.0, patched)

`go.mod` replaces `golang.org/x/crypto` with this directory. It holds the
v0.55.0 source of only the packages Mirage builds (`ssh` and its
dependencies), copied unmodified from the module cache, plus the patches
below. Every patched line is marked `MIRAGE:`; `grep -rn MIRAGE: .` lists
them. Each patch removes a way to tell this server from OpenSSH 8.9p1
(Ubuntu 22.04) before login, measured against
`openssh-server 1:8.9p1-3ubuntu0.18`, and has a test in
`ssh/mirage_patches_test.go` that fails without it.

| Patch | File | Upstream behaviour (the tell) | Now |
|---|---|---|---|
| Zero padding before NEWKEYS | `ssh/cipher.go` | random padding in unencrypted packets: Bitter Harvest's one-packet distinguisher | zeros, as OpenSSH |
| Client identification line | `ssh/transport.go`, `ssh/server.go` | skips non-SSH lines, accepts any version, 255-byte limit, no reply | sshd's rules and messages ("Invalid SSH identification string.", "Protocol major versions differ."), 8 KiB limit |
| KEXINIT before reading | `ssh/handshake.go` | a malformed first client packet could close the connection before the server's KEXINIT went out | KEXINIT always first |
| Auth method order | `ssh/server.go` | `password,publickey` | `publickey,password[,keyboard-interactive]` |
| RSA host key order | `ssh/common.go`, `ssh/handshake.go` | `rsa-sha2-256,rsa-sha2-512` | `rsa-sha2-512,rsa-sha2-256` (advertised list only) |

Upstream tests are kept and pass, except one case changed on purpose
(`TestClientVersion`: lines before the client's identification string are
now rejected, as sshd does). `session_test.go` and `example_test.go` were
dropped because they import packages not copied here.

### Upgrading

1. Copy the same package list from the new version's module cache over
   this directory (`ssh`, `ssh/internal/bcrypt_pbkdf`, `blowfish`,
   `chacha20`, `curve25519`, `cryptobyte`, `cryptobyte/asn1`,
   `internal/poly1305`, `internal/alias`, with `ssh/*_test.go` and
   `ssh/testdata`).
2. Re-apply each `MIRAGE:` hunk (diff against the old version's cache).
3. `cd third_party/golang.org/x/crypto && go test ./ssh/`, then
   `scripts/compare_ssh_fingerprint.py` and `scripts/detection_checks.py`
   against a real 8.9 host.

Security fixes upstream must be pulled the same way; check the x/crypto
release notes when bumping `golang.org/x/crypto` would otherwise be due.
