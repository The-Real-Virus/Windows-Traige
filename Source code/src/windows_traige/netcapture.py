"""Offline PCAP and PCAPNG metadata reader. Packet contents stay in the original file."""

import ipaddress
import struct
from datetime import datetime, timedelta, timezone

from .common import Invalid, check_cancel

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
SECTION = b"\x0a\x0d\x0d\x0a"
BYTE_ORDER = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}
MAX_BLOCK = 2 * 1024 ** 2
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def read_exact(stream, count):
    data = stream.read(count)
    if len(data) != count:
        raise Invalid("The packet capture ends inside a record")
    return data


def packet_time(ticks, units, offset=0):
    seconds, fraction = divmod(ticks, units)
    try:
        value = EPOCH + timedelta(seconds=seconds + offset, microseconds=fraction * 1_000_000 // units)
    except OverflowError as exc:
        raise Invalid("Packet timestamp is outside the supported range") from exc
    return value.isoformat()


def classic(stream, magic, cancel):
    endian, units = PCAP_MAGICS[magic]
    major, minor, _, _, limit, link = struct.unpack(endian + "HHIIII", read_exact(stream, 20))
    if (major, minor) != (2, 4) or not 0 < limit <= MAX_BLOCK:
        raise Invalid("Unsupported PCAP version or packet size")
    while header := stream.read(16):
        check_cancel(cancel)
        if len(header) != 16:
            raise Invalid("The packet capture ends inside a record")
        seconds, fraction, captured, original = struct.unpack(endian + "IIII", header)
        if fraction >= units or captured > min(limit, original):
            raise Invalid("Invalid PCAP timestamp or packet length")
        packet = read_exact(stream, captured)
        yield packet_time(seconds * units + fraction, units), link & 0xffff, packet


def interface(body, endian):
    if len(body) < 8:
        raise Invalid("Invalid PCAPNG interface block")
    link, _, limit = struct.unpack_from(endian + "HHI", body)
    offset, units = 0, 1_000_000
    cursor = 8
    while cursor < len(body):
        if cursor + 4 > len(body):
            raise Invalid("Invalid PCAPNG interface option")
        code, length = struct.unpack_from(endian + "HH", body, cursor)
        cursor += 4
        padded = (length + 3) & ~3
        if cursor + padded > len(body):
            raise Invalid("Invalid PCAPNG interface option length")
        if code == 0:
            if length or cursor != len(body):
                raise Invalid("Invalid PCAPNG end of options")
            break
        if code == 9:
            if length != 1:
                raise Invalid("Invalid PCAPNG timestamp resolution")
            value = body[cursor]
            base, power = (2, value & 0x7f) if value & 0x80 else (10, value)
            if power > 63:
                raise Invalid("Unsupported PCAPNG timestamp resolution")
            units = base ** power
        if code == 14:
            if length != 8:
                raise Invalid("Invalid PCAPNG timestamp offset")
            offset = struct.unpack_from(endian + "q", body, cursor)[0]
        cursor += padded
    return link, limit or MAX_BLOCK, units, offset


def next_generation(stream, kind, cancel):
    endian, interfaces = None, []
    while kind:
        check_cancel(cancel)
        if len(kind) != 4:
            raise Invalid("The packet capture ends inside a block")
        size_raw = read_exact(stream, 4)
        section = kind == SECTION
        order = read_exact(stream, 4) if section else b""
        if section:
            endian = BYTE_ORDER.get(order)
        if endian is None:
            raise Invalid("Invalid PCAPNG byte order")
        size = struct.unpack(endian + "I", size_raw)[0]
        if size < (28 if section else 12) or size > MAX_BLOCK or size % 4:
            raise Invalid("Invalid PCAPNG block size")
        body = order + read_exact(stream, size - 12 - len(order))
        if read_exact(stream, 4) != size_raw:
            raise Invalid("PCAPNG block lengths disagree")
        if section:
            if struct.unpack_from(endian + "HH", body, 4) != (1, 0):
                raise Invalid("Unsupported PCAPNG section version")
            interfaces.clear()
        else:
            block = struct.unpack(endian + "I", kind)[0]
            if block == 1:
                if len(interfaces) >= 256:
                    raise Invalid("PCAPNG exceeds the supported interface count")
                interfaces.append(interface(body, endian))
            elif block == 6:
                if len(body) < 20:
                    raise Invalid("Invalid PCAPNG enhanced packet block")
                index, high, low, captured, original = struct.unpack_from(endian + "IIIII", body)
                if index >= len(interfaces) or 20 + ((captured + 3) & ~3) > len(body):
                    raise Invalid("Invalid PCAPNG packet reference or length")
                link, limit, units, offset = interfaces[index]
                if captured > min(limit, original):
                    raise Invalid("Invalid PCAPNG packet length")
                yield packet_time((high << 32) | low, units, offset), link, body[20:20 + captured]
            elif block in {2, 3}:
                yield None, -1, b""
        kind = stream.read(4)


def packets(path, cancel=None):
    with path.open("rb") as stream:
        magic = read_exact(stream, 4)
        suffix = path.suffix.lower()
        if magic == SECTION and suffix == ".pcapng":
            yield from next_generation(stream, magic, cancel)
        elif magic in PCAP_MAGICS and suffix == ".pcap":
            yield from classic(stream, magic, cancel)
        else:
            raise Invalid("The file is not a supported PCAP or PCAPNG capture")


def connection(link, packet):
    start = 0
    if link == 1:
        if len(packet) < 14:
            return None
        protocol = int.from_bytes(packet[12:14], "big")
        start = 14
        for _ in range(2):
            if protocol not in {0x8100, 0x88a8} or len(packet) < start + 4:
                break
            protocol = int.from_bytes(packet[start + 2:start + 4], "big")
            start += 4
        if protocol not in {0x0800, 0x86dd}:
            return None
    elif link not in {101, 228, 229}:
        return None
    ip = packet[start:]
    if not ip:
        return None
    version = ip[0] >> 4
    if version == 4 and len(ip) >= 20:
        end = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], "big")
        if end < 20 or end + 4 > min(total, len(ip)) or int.from_bytes(ip[6:8], "big") & 0x1fff:
            return None
        transport, source, destination = ip[9], ip[12:16], ip[16:20]
    elif version == 6 and len(ip) >= 44 and int.from_bytes(ip[4:6], "big") >= 4:
        end = 40
        transport, source, destination = ip[6], ip[8:24], ip[24:40]
    else:
        return None
    if transport not in {6, 17}:
        return None
    port, remote = struct.unpack_from("!HH", ip, end)
    return {"ip": str(ipaddress.ip_address(source)), "remote_ip": str(ipaddress.ip_address(destination)),
            "port": port, "remote_port": remote, "protocol": "TCP" if transport == 6 else "UDP"}
