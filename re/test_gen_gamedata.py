import struct
import unittest

from gen_gamedata import parse_bank_slot_extend


class BankSlotExtendParserTest(unittest.TestCase):
    def test_parses_client_rows_and_disabled_costume_options(self):
        rows = []
        for level in range(1, 31):
            row = bytearray(20)
            row[0:4] = bytes((level, level, 1, 3))
            struct.pack_into("<I", row, 4, 837000002)
            struct.pack_into("<BH", row, 8, 12, 36 + (level - 1) * 12)
            if level <= 28:
                row[11:13] = bytes((1, 3))
                struct.pack_into("<I", row, 13, 837000002)
                struct.pack_into("<BH", row, 17, 12, 60 + (level - 1) * 12)
            rows.append(row)
        table = struct.pack("<I", len(rows)) + b"".join(rows) + bytes(34)
        expected = [
            (level, 837000002, 12, 36 + (level - 1) * 12,
             837000002 if level <= 28 else 0, 12 if level <= 28 else 0,
             60 + (level - 1) * 12 if level <= 28 else 0)
            for level in range(1, 31)
        ]
        self.assertEqual(parse_bank_slot_extend(table), expected)

    def test_missing_required_table_fails_clearly(self):
        with self.assertRaisesRegex(ValueError, "required client table tb_Bank_Slot_Extend.res is missing"):
            parse_bank_slot_extend(None)

    def test_empty_table_fails_clearly(self):
        with self.assertRaisesRegex(ValueError, "no Add Slots expansion rows"):
            parse_bank_slot_extend(struct.pack("<I", 0) + bytes(34))


if __name__ == "__main__":
    unittest.main()
