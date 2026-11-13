# FreeRADIUS for Abyssal Arsenal (deploy/freeradius/README.md).
#
# The official image plus Samba's winbind, so PEAP/MSCHAPv2 logins can be
# checked against Active Directory with ntlm_auth. Without AD_REALM set it
# behaves exactly like the official image (EAP-TLS and MAB only).
FROM freeradius/freeradius-server:3.2.7

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      winbind samba-common-bin krb5-user \
 && rm -rf /var/lib/apt/lists/* \
 # ntlm_auth talks to winbindd over its privileged pipe, which only the
 # winbindd_priv group can open. FreeRADIUS drops to freerad with
 # initgroups(), so the supplementary group carries over.
 && (getent group winbindd_priv >/dev/null || groupadd --system winbindd_priv) \
 && usermod -aG winbindd_priv freerad \
 # The stock smb.conf and krb5.conf are rewritten from AD_* at startup.
 && rm -f /etc/samba/smb.conf /etc/krb5.conf

COPY entrypoint.sh /usr/local/bin/abyssal-freeradius-entrypoint
COPY abyssal-ntlm-auth abyssal-ad-groups /usr/local/bin/
RUN chmod 755 /usr/local/bin/abyssal-freeradius-entrypoint /usr/local/bin/abyssal-ntlm-auth \
      /usr/local/bin/abyssal-ad-groups

# Internal attributes for AD groups (0.2.8 P1).
COPY dictionary.abyssal /etc/freeradius/dictionary.abyssal
RUN printf '\n$INCLUDE dictionary.abyssal\n' >> /etc/freeradius/dictionary

ENTRYPOINT ["/usr/local/bin/abyssal-freeradius-entrypoint"]
CMD ["freeradius", "-f"]
