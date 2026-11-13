"""Sends one SNMP v2c trap, the way a switch would, for
deploy/test/radius-e2e.sh.

    python send_trap.py <host> <port> <community> linkdown|linkup <ifIndex>
    python send_trap.py <host> <port> <community> mac <mac> <vlan> <bridge port>
"""

import socket
import sys

SNMP_TRAP_OID = [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]
LINK_DOWN = [1, 3, 6, 1, 6, 3, 1, 1, 5, 3]
LINK_UP = [1, 3, 6, 1, 6, 3, 1, 1, 5, 4]
IF_INDEX = [1, 3, 6, 1, 2, 1, 2, 2, 1, 1]
CISCO_MAC_CHANGED = [1, 3, 6, 1, 4, 1, 9, 9, 215, 2, 0, 1]
CISCO_MAC_CHANGED_MSG = [1, 3, 6, 1, 4, 1, 9, 9, 215, 1, 1, 8, 1, 2]


def tlv(tag, body):
    n = len(body)
    if n < 128:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + body


def integer(n):
    return tlv(0x02, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True))


def oid(parts):
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)


def varbind(name, value):
    return tlv(0x30, oid(name) + value)


def trap(community, trap_oid, binds):
    vbs = varbind([1, 3, 6, 1, 2, 1, 1, 3, 0], tlv(0x43, b"\x01\x00"))
    vbs += varbind(SNMP_TRAP_OID, oid(trap_oid))
    vbs += b"".join(binds)
    pdu = tlv(0xA7, integer(1) + integer(0) + integer(0) + tlv(0x30, vbs))
    return tlv(0x30, integer(1) + tlv(0x04, community.encode()) + pdu)


def main():
    host, port, community, kind = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    if kind in ("linkdown", "linkup"):
        index = int(sys.argv[5])
        packet = trap(
            community,
            LINK_DOWN if kind == "linkdown" else LINK_UP,
            [varbind(IF_INDEX + [index], integer(index))],
        )
    elif kind == "mac":
        mac = bytes.fromhex(sys.argv[5].replace(":", ""))
        vlan, bridge_port = int(sys.argv[6]), int(sys.argv[7])
        record = bytes([1]) + vlan.to_bytes(2, "big") + mac + bridge_port.to_bytes(2, "big") + b"\x00"
        packet = trap(community, CISCO_MAC_CHANGED, [varbind(CISCO_MAC_CHANGED_MSG + [1], tlv(0x04, record))])
    else:
        sys.exit(f"unknown trap kind {kind}")
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(packet, (host, port))


if __name__ == "__main__":
    main()
