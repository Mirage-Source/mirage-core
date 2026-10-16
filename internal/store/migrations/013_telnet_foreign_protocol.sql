-- First line of a telnet session whose client spoke another protocol
-- (HTTP, SIP, RTSP, TLS, SSH); such lines are not stored as auth attempts.
ALTER TABLE telnet_session_meta ADD COLUMN IF NOT EXISTS foreign_protocol_line TEXT;
