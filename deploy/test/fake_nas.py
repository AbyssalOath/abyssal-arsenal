"""A stand-in NAS for deploy/test/radius-e2e.sh: answers RFC 5176
Disconnect-Requests and CoA-Requests with a signed ACK, the way a switch
would, and logs each one (code, Acct-Session-Id, Calling-Station-Id) so the
test can see what Panopticon's CoA sent.

    python fake_nas.py <address> <port> <shared secret>
"""

import hashlib
import socket
import sys

DISCONNECT_REQUEST, DISCONNECT_ACK = 40, 41
COA_REQUEST, COA_ACK = 43, 44
ATTR_USER_NAME, ATTR_CALLING_STATION_ID, ATTR_ACCT_SESSION_ID = 1, 31, 44


def attributes(data):
    """(type, value) pairs of a packet's attributes."""
    out, i = [], 20
    while i + 2 <= len(data):
        t, length = data[i], data[i + 1]
        if length < 2:
            break
        out.append((t, data[i + 2 : i + length]))
        i += length
    return out


def main():
    address, port, secret = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, port))
    print(f"fake NAS listening on {address}:{port}", flush=True)
    while True:
        data, peer = sock.recvfrom(4096)
        if len(data) < 20:
            continue
        code, ident, request_auth = data[0], data[1], data[4:20]
        reply_code = {DISCONNECT_REQUEST: DISCONNECT_ACK, COA_REQUEST: COA_ACK}.get(code)
        if reply_code is None:
            continue
        attrs = dict(attributes(data))
        print(
            "request code=%d session=%s csid=%s"
            % (
                code,
                attrs.get(ATTR_ACCT_SESSION_ID, b"").decode(errors="replace"),
                attrs.get(ATTR_CALLING_STATION_ID, b"").decode(errors="replace"),
            ),
            flush=True,
        )
        # RFC 5176: Response Authenticator =
        # MD5(Code + Identifier + Length + Request Authenticator + Attributes + Secret).
        header = bytes([reply_code, ident, 0, 20])
        auth = hashlib.md5(header + request_auth + secret).digest()
        sock.sendto(header + auth, peer)


if __name__ == "__main__":
    main()
