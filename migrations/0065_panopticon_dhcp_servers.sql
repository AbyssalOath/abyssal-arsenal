-- Panopticon 0.2.9 Q4 (docs/roadmap/0.2.9.md): rogue DHCP server detection.
--
-- Every DHCP server the capture has seen: from the server identifier
-- (option 54) in clients' REQUESTs, which also arrive through relays and say
-- which server a client actually chose, and from OFFER/ACK/NAK replies on
-- the captured segment. A server not on panopticon.dhcp_allowed_servers is a
-- rogue; alerted_at keeps the alert to once a day per server.
CREATE TABLE panopticon_dhcp_servers (
    server_ip        VARCHAR(45)  NOT NULL PRIMARY KEY,
    -- The Ethernet source of an unrelayed reply: the server itself. A
    -- relayed reply's source is the relay, so it isn't recorded.
    server_mac       VARCHAR(17)  NULL,
    first_seen_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    -- Replies seen from it, and client REQUESTs naming it.
    replies          INT UNSIGNED NOT NULL DEFAULT 0,
    chosen           INT UNSIGNED NOT NULL DEFAULT 0,
    last_client_mac  VARCHAR(17)  NULL,
    alerted_at       DATETIME(6)  NULL,
    KEY idx_dhcp_server_seen (last_seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
