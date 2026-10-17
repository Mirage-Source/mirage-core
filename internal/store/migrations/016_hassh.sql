-- SSH client fingerprint from its KEXINIT (see internal/sshfp): hassh is
-- md5 of hassh_algorithms. Empty for telnet and for clients that never
-- sent a KEXINIT.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS hassh TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS hassh_algorithms TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_sessions_hassh ON sessions(hassh) WHERE hassh <> '';
