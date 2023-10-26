from struct import Struct
from typing import Callable

from wizproxy.proto.bytes import U32

CHALLENGE_ID = 0xF1

CONTROL_DISABLE = 1 << 5
CONTROL_INCLUDE_OFFSETS = 1 << 9
CONTROL_INCLUDE_MODULES = 1 << 12
CONTROL_OBFUSCATE = 1 << 17

CHALLENGE_BUF = Struct("<III")


class ClientSig:
    __slots__ = ("offsets", "modules", "code")

    def __init__(self, data: bytes):
        offsets_len = U32.unpack_from(data)[0]
        self.offsets = data[4 : 4 + offsets_len]

        modules_start = 4 + offsets_len
        modules_len = U32.unpack_from(data, modules_start)[0]
        self.modules = data[modules_start + 4 : modules_start + 4 + modules_len]

        code_start = modules_start + 4 + modules_len
        code_len = U32.unpack_from(data, code_start)[0]
        self.code = data[code_start + 4 : code_start + 4 + code_len]


def _fnv_1a_round(acc: int, b: int) -> int:
    acc = (acc ^ b) * 0x01000193
    return acc & 0xFFFF_FFFF


def _fnv_round(acc: int, b: int) -> int:
    acc = (acc * 0x01000193) ^ b
    return acc & 0xFFFF_FFFF


def _jenkins_one_at_a_time_round(acc: int, b: int) -> int:
    acc = (acc + b) & 0xFFFF_FFFF
    acc = (acc + (acc << 10)) & 0xFFFF_FFFF
    return acc ^ (acc >> 6)


def _pjw_hash_round(acc: int, b: int) -> int:
    acc = ((acc << 4) + b) & 0xFFFF_FFFF

    high = acc & 0xF000_0000
    if high != 0:
        acc ^= high >> 24

    return acc & ~high


def chunk_size(spec: int) -> int:
    return ((spec & 0x3C) >> 2) + 1


def seed(spec: int) -> int:
    return spec >> 8


def rounds(spec: int) -> int:
    return ((spec & 0xC0) >> 6) + 1


def processing_func(spec: int) -> Callable[[int, int], int]:
    algo = spec & 0b11
    if algo == 0:
        return _fnv_1a_round
    elif algo == 1:
        return _fnv_round
    elif algo == 2:
        return _jenkins_one_at_a_time_round
    else:
        return _pjw_hash_round


def scramble_buffer(data: bytes, key: int) -> bytes:
    buf = bytearray()

    key_bytes = U32.pack(key)
    step = (
        (key & (1 << 3)) >> (3 - 0)
        | (key & (1 << 5)) >> (5 - 1)
        | (key & (1 << 7)) >> (7 - 2)
        | (key & (1 << 14)) >> (14 - 3)
        | (key & (1 << 18)) >> (18 - 4)
    )

    for b in data:
        if step != 0 and len(buf) != 0 and len(buf) % step == 0:
            buf.append(buf[-1])
        buf.append(key_bytes[len(buf) & 3] ^ b)

    return buf


def build_signature_buffer(sig: ClientSig, flags: int, key: int) -> bytes:
    result = bytearray()

    # Process offset data into the buffer, if requested.
    if (flags & CONTROL_INCLUDE_OFFSETS) != 0:
        result.extend(scramble_buffer(sig.offsets, key))

    # Process modules data into the buffer, if requested.
    if (flags & CONTROL_INCLUDE_MODULES) != 0:
        result.extend(scramble_buffer(sig.modules, key))

    # Always process code data into the buffer.
    result.extend(scramble_buffer(sig.code, key))

    return result


def challenge(sig: ClientSig, message: memoryview) -> int:
    # Make sure the buffer contains what we need
    if len(message) < 12:
        raise ValueError("received too few bytes to perform challenge")

    # Parse challenge inputs.
    control_mask, spec, key = CHALLENGE_BUF.unpack_from(message)

    # Skip the challenge if it is disabled.
    if (control_mask & CONTROL_DISABLE) != 0:
        return 0

    # Build the signature buffer we want to hash.
    buf = build_signature_buffer(sig, control_mask, key)
    buf_len = len(buf)

    # XOR the buffer with the entire control mask if obfuscation
    # of the data is requested.
    if (control_mask & CONTROL_OBFUSCATE) != 0:
        control_bytes = U32.unpack(control_mask)[0]
        for i in range(len(buf)):
            buf[i] ^= control_bytes[i & 3]

    # Produce the final hash over the signature buffer.
    result = seed(spec)
    func = processing_func(spec)
    size = chunk_size(spec)
    for _ in range(rounds(spec)):
        for i in range(size):
            for b in range(i, buf_len, size):
                result = func(result, buf[b])

    return result
