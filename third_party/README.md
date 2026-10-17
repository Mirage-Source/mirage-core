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
| Rejection CRLF and reset | `ssh/transport.go` | (after the row above) message and CRLF always delivered, clean close | sshd's two-write `send_error`: if client bytes are still unread at close, the client gets the message without CRLF and a reset; otherwise message, CRLF, clean close. Wrappers expose `NetConn()` so the socket can be set to reset |
| KEXINIT before reading | `ssh/handshake.go` | a malformed first client packet could close the connection before the server's KEXINIT went out | KEXINIT always first |
| Auth method order | `ssh/server.go` | `password,publickey` | `publickey,password[,keyboard-interactive]` |
| RSA host key order | `ssh/common.go`, `ssh/handshake.go` | `rsa-sha2-256,rsa-sha2-512` | `rsa-sha2-512,rsa-sha2-256` (advertised list only) |

`ssh/mirage_algorithms.go` also registers two algorithms 8.9 offers that
upstream lacks: `diffie-hellman-group18-sha512` (RFC 3526 group 18, prime
checked against the 8.9 sshd binary) and `hmac-sha1-etm@openssh.com`.
`ssh/mirage_interop_test.go` negotiates each with the system `ssh` client.
Still missing: `sntrup761x25519-sha512@openssh.com` and the umac MACs.

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
