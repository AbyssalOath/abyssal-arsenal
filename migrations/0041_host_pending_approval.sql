-- Hosts enrolled with the AAT (the reusable, CID-style install token --
-- see abyssal_agent_protocol::aat) while "require approval" is on start out
-- pending: enrolled, holding a credential, but refused on the agent
-- WebSocket until an admin approves them on /admin/hosts. Every existing
-- host, and every host enrolled any other way, is approved (0).
ALTER TABLE hosts
    ADD COLUMN pending_approval TINYINT(1) NOT NULL DEFAULT 0 AFTER agent_version;
