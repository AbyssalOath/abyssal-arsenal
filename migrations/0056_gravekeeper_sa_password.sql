-- Gravekeeper (docs/roadmap/ad-management.md, *Service account*): warn before
-- the delegated service account's password expires, and rotate it.
--
-- The expiry is read by every delegation check (on save and the daily
-- re-check): `msDS-UserPasswordExpiryTimeComputed` and `PasswordNeverExpires`.
-- Both NULL means not known yet (no check since, or an agent older than 0.2.6).
--
-- service_account_pending_sealed holds a new password while a rotation is in
-- flight: it is sealed and stored *before* AD is asked to change anything, and
-- replaces service_account_sealed only once AD confirms. If the outcome is
-- unclear (a timeout), the next check tries the current password, then the
-- pending one, and keeps whichever works -- so a password AD accepted is never
-- lost.
ALTER TABLE directory_domains
    ADD COLUMN sa_password_expires_at         DATETIME(6) NULL,
    ADD COLUMN sa_password_never_expires      TINYINT(1)  NULL,
    ADD COLUMN service_account_pending_sealed TEXT        NULL;
