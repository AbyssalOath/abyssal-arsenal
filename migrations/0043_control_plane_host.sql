-- The control plane's own server can run an agent (install.sh enrolls one),
-- the way Puppet, Salt or Wazuh manage their own server. Flagging that host
-- turns on the guardrails in abyssal_hosts::control_plane_guard (no
-- isolation, no inline IPS, no closing its own ports, no stopping Docker or
-- its own containers, no reformatting Docker's disk), shows a "Control
-- plane" badge, and lists it first.
ALTER TABLE hosts
    ADD COLUMN is_control_plane TINYINT(1) NOT NULL DEFAULT 0 AFTER pending_approval;

-- A token minted by `abyssal-arsenal hosts control-plane-token` (run by
-- install.sh) flags the host that enrolls with it.
ALTER TABLE host_enrollment_tokens
    ADD COLUMN control_plane TINYINT(1) NOT NULL DEFAULT 0;
