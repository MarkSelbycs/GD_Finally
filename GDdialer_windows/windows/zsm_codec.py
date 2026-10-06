"""Pure-Python reconstruction of the bundled zsm AES-style body codec."""

from __future__ import annotations

import re
from typing import Iterable


_KEY1 = b'F-hxkOhsAP~%"\'Io'
_KEY2 = b"FX}z&LYWBVHbAO_U"
_IV = b"Ck#:OVEbRa/P_wUz"

_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F,
    0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3,
    0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19,
    0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B,
    0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4,
    0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE,
    0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B,
    0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D,
    0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28,
    0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB,
    0x16,
)

_INV_SBOX = tuple(next(index for index, value in enumerate(_SBOX) if value == target) for target in range(256))
_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _round_keys(key: bytes) -> list[bytes]:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    words = [bytearray(key[index:index + 4]) for index in range(0, 16, 4)]
    for index in range(4, 44):
        temp = bytearray(words[index - 1])
        if index % 4 == 0:
            temp = bytearray((_SBOX[temp[1]], _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]))
            temp[0] ^= _RCON[index // 4]
        words.append(bytearray(a ^ b for a, b in zip(words[index - 4], temp)))
    return [bytes().join(bytes(word) for word in words[index:index + 4]) for index in range(0, 44, 4)]


def _xtime(value: int) -> int:
    return ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF


def _mul(value: int, factor: int) -> int:
    result = 0
    while factor:
        if factor & 1:
            result ^= value
        value = _xtime(value)
        factor >>= 1
    return result


def _add_round_key(state: bytearray, key: bytes) -> None:
    for index in range(16):
        state[index] ^= key[index]


def _shift_rows(state: bytearray) -> None:
    original = state[:]
    for row in range(4):
        for column in range(4):
            state[row + 4 * column] = original[row + 4 * ((column + row) % 4)]


def _inv_shift_rows(state: bytearray) -> None:
    original = state[:]
    for row in range(4):
        for column in range(4):
            state[row + 4 * column] = original[row + 4 * ((column - row) % 4)]


def _mix_columns(state: bytearray) -> None:
    for column in range(4):
        offset = column * 4
        a0, a1, a2, a3 = state[offset:offset + 4]
        state[offset:offset + 4] = bytes(
            (
                _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3,
                a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3,
                a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3),
                _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2),
            )
        )


def _inv_mix_columns(state: bytearray) -> None:
    for column in range(4):
        offset = column * 4
        a0, a1, a2, a3 = state[offset:offset + 4]
        state[offset:offset + 4] = bytes(
            (
                _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9),
                _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13),
                _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11),
                _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14),
            )
        )


def _encrypt_block(block: bytes, keys: list[bytes]) -> bytes:
    state = bytearray(block)
    _add_round_key(state, keys[0])
    for round_key in keys[1:-1]:
        for index in range(16):
            state[index] = _SBOX[state[index]]
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_key)
    for index in range(16):
        state[index] = _SBOX[state[index]]
    _shift_rows(state)
    _add_round_key(state, keys[-1])
    return bytes(state)


def _decrypt_block(block: bytes, keys: list[bytes]) -> bytes:
    state = bytearray(block)
    _add_round_key(state, keys[-1])
    for round_key in reversed(keys[1:-1]):
        _inv_shift_rows(state)
        for index in range(16):
            state[index] = _INV_SBOX[state[index]]
        _add_round_key(state, round_key)
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    for index in range(16):
        state[index] = _INV_SBOX[state[index]]
    _add_round_key(state, keys[0])
    return bytes(state)


def _blocks(data: bytes) -> Iterable[bytes]:
    for offset in range(0, len(data), 16):
        yield data[offset:offset + 16]


def _transpose(block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    return bytes(block[column + 4 * row] for column in range(4) for row in range(4))


def _layout_encrypt(block: bytes, keys: list[bytes]) -> bytes:
    transposed = _transpose(block)
    encrypted = _encrypt_block(transposed, keys)
    return _transpose(encrypted)


def _layout_decrypt(block: bytes, keys: list[bytes]) -> bytes:
    transposed = _transpose(block)
    decrypted = _decrypt_block(transposed, keys)
    return _transpose(decrypted)


class PythonZsmCodec:
    """Reconstructed body codec: zero-padded AES-128-CBC with IV prefix."""

    def __init__(self, key: bytes = _KEY1, iv: bytes = _IV):
        self._keys = (_round_keys(_transpose(key)), _round_keys(_transpose(_KEY2)))
        self._iv = iv

    @staticmethod
    def _cbc_encrypt(raw: bytes, keys: list[bytes], iv: bytes) -> bytes:
        padded = raw + b"\0" * ((16 - len(raw) % 16) % 16)
        previous = iv
        encrypted = bytearray()
        for block in _blocks(padded):
            mixed = bytes(a ^ b for a, b in zip(block, previous))
            previous = _layout_encrypt(mixed, keys)
            encrypted.extend(previous)
        return bytes(encrypted)

    @staticmethod
    def _cbc_decrypt(data: bytes, keys: list[bytes], iv: bytes) -> bytes:
        if len(data) % 16:
            raise ValueError("zsm response has an invalid block length")
        previous = iv
        plaintext = bytearray()
        for block in _blocks(data):
            decrypted = _layout_decrypt(block, keys)
            plaintext.extend(a ^ b for a, b in zip(decrypted, previous))
            previous = block
        return bytes(plaintext)

    def encode(self, xml_body: str) -> bytes:
        raw = xml_body.encode("utf-8") + b"\0"
        first = self._iv + self._cbc_encrypt(raw, self._keys[0], self._iv)
        second = self._iv + self._cbc_encrypt(first, self._keys[1], self._iv)
        return second.hex().upper().encode("ascii")

    def decode(self, body: bytes) -> str:
        compact = re.sub(rb"\s+", b"", body)
        if len(compact) % 2 or not re.fullmatch(rb"[0-9A-Fa-f]*", compact):
            raise ValueError("zsm response is not an ASCII hex body")
        decoded = bytes.fromhex(compact.decode("ascii"))
        if len(decoded) < 32 or (len(decoded) - 16) % 16:
            raise ValueError("zsm response has an invalid block length")
        iv, encrypted = decoded[:16], decoded[16:]
        second_plain = self._cbc_decrypt(encrypted, self._keys[1], iv)
        if len(second_plain) < 16 or (len(second_plain) - 16) % 16:
            raise ValueError("zsm response is missing the inner IV prefix")
        plain = self._cbc_decrypt(second_plain[16:], self._keys[0], second_plain[:16])
        return plain.rstrip(b"\0").decode("utf-8")


__all__ = ["PythonZsmCodec"]
