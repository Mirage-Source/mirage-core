-- Port the client targeted on the relay, from the PROXY header's dst-port.
-- NULL for direct connections, where server_port already answers it.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS target_port INTEGER;
