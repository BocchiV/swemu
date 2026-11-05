import struct
import unittest

import gen_gamedata


class RandomBoxDataTests(unittest.TestCase):
    def test_client_row_decodes_weighted_gruton_coin_rewards(self) -> None:
        row = bytes.fromhex(
            "a279113b011027000000000000000000000000d007c409d007a604e80384032c"
            "0164000a000000000000000000000000000000000000000000e70baf2fe70baf"
            "2fe70baf2fe70baf2fe70baf2fe70baf2fe70baf2fe70baf2fe70baf2f000000"
            "0000000000000000000000000000000000000000000a00000019000000230000"
            "00320000004b00000064000000b4000000fa000000f401000000000000000000"
            "0000000000000000000000000000000000"
        )
        table = struct.pack("<I", 1) + row + bytes(34)

        self.assertEqual(
            gen_gamedata.parse_random_boxes(table),
            {
                991000994: [
                    (800000999, 10, 2000),
                    (800000999, 25, 2500),
                    (800000999, 35, 2000),
                    (800000999, 50, 1190),
                    (800000999, 75, 1000),
                    (800000999, 100, 900),
                    (800000999, 180, 300),
                    (800000999, 250, 100),
                    (800000999, 500, 10),
                ]
            },
        )

    def test_weighted_no_reward_is_kept_and_empty_box_is_omitted(self) -> None:
        weighted_empty = bytearray(177)
        struct.pack_into("<I", weighted_empty, 0, 14787)
        struct.pack_into("<H", weighted_empty, 19, 5)
        no_outcomes = bytearray(177)
        struct.pack_into("<I", no_outcomes, 0, 10002)
        table = struct.pack("<I", 2) + weighted_empty + no_outcomes + bytes(34)

        self.assertEqual(
            gen_gamedata.parse_random_boxes(table),
            {14787: [(0, 0, 5)]},
        )


if __name__ == "__main__":
    unittest.main()
