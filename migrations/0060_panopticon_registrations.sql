-- 0.2.7 N5 (docs/roadmap/0.2.7.md): the registration portal. One row per
-- device MAC that asked for guest access on the registration VLAN.
--   pending   waiting for staff approval (sponsor mode)
--   approved  guest access until expires_at
--   denied    refused by staff
--   revoked   access withdrawn by staff before it expired
--   expired   expires_at passed (the expiry sweep re-authorizes the device)
-- RADIUS (unknown_action = 'register') puts an unknown device on the guest
-- VLAN while its row is approved and unexpired, else on the registration VLAN.
CREATE TABLE panopticon_registrations (
    mac_address  VARCHAR(17)  NOT NULL PRIMARY KEY,
    name         VARCHAR(100) NOT NULL,
    email        VARCHAR(255) NULL,
    status       VARCHAR(16)  NOT NULL,
    requested_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    decided_at   DATETIME(6)  NULL,
    decided_by   VARCHAR(255) NULL,
    expires_at   DATETIME(6)  NULL,
    KEY idx_registrations_status (status, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
