-- Opening bytes (up to 4 KiB, base64, as received) of a telnet client that
-- spoke another protocol; foreign_protocol_line keeps only the first line.
ALTER TABLE telnet_session_meta ADD COLUMN IF NOT EXISTS foreign_payload_b64 TEXT;
