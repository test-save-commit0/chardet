from .charsetprober import CharSetProber
from .enums import ProbingState


class UTF1632Prober(CharSetProber):
    '\n    This class simply looks for occurrences of zero bytes, and infers\n    whether the file is UTF16 or UTF32 (low-endian or big-endian)\n    For instance, files looking like ( \x00 \x00 \x00 [nonzero] )+\n    have a good probability to be UTF32BE.  Files looking like ( \x00 [nonzero] )+\n    may be guessed to be UTF16BE, and inversely for little-endian varieties.\n    '
    MIN_CHARS_FOR_DETECTION = 20
    EXPECTED_RATIO = 0.94

    def __init__(self):
        super().__init__()
        self.position = 0
        self.zeros_at_mod = [0] * 4
        self.nonzeros_at_mod = [0] * 4
        self._state = ProbingState.DETECTING
        self.quad = [0, 0, 0, 0]
        self.invalid_utf16be = False
        self.invalid_utf16le = False
        self.invalid_utf32be = False
        self.invalid_utf32le = False
        self.first_half_surrogate_pair_detected_16be = False
        self.first_half_surrogate_pair_detected_16le = False
        self.reset()

    def validate_utf32_characters(self, quad):
        """
        Validate if the quad of bytes is valid UTF-32.

        UTF-32 is valid in the range 0x00000000 - 0x0010FFFF
        excluding 0x0000D800 - 0x0000DFFF

        https://en.wikipedia.org/wiki/UTF-32
        """
        value = (quad[0] << 24) | (quad[1] << 16) | (quad[2] << 8) | quad[3]
        return 0x00000000 <= value <= 0x0010FFFF and not (0x0000D800 <= value <= 0x0000DFFF)

    def validate_utf16_characters(self, pair):
        """
        Validate if the pair of bytes is  valid UTF-16.

        UTF-16 is valid in the range 0x0000 - 0xFFFF excluding 0xD800 - 0xFFFF
        with an exception for surrogate pairs, which must be in the range
        0xD800-0xDBFF followed by 0xDC00-0xDFFF

        https://en.wikipedia.org/wiki/UTF-16
        """
        value = (pair[0] << 8) | pair[1]
        if 0xD800 <= value <= 0xDBFF:
            # First half of a surrogate pair
            if not self.first_half_surrogate_pair_detected_16be:
                self.first_half_surrogate_pair_detected_16be = True
                return True
            else:
                return False
        elif 0xDC00 <= value <= 0xDFFF:
            # Second half of a surrogate pair
            if self.first_half_surrogate_pair_detected_16be:
                self.first_half_surrogate_pair_detected_16be = False
                return True
            else:
                return False
        else:
            # Regular UTF-16 character
            self.first_half_surrogate_pair_detected_16be = False
            return 0x0000 <= value < 0xD800 or 0xE000 <= value <= 0xFFFF
