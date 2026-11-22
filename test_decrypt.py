"""Tests for decrypt.py (smarty_dsmr_proxy).

Run from the directory that contains decrypt.py:

    pip install pycryptodomex pyserial
    python3 -m unittest -v test_decrypt          # or: pytest -v test_decrypt.py

No serial hardware is needed: the meter is replaced by an in-memory fake
connection, and time is driven by a fake clock so the tests run in seconds.

What is covered
  * normal operation (clean stream, leading garbage, odd chunk sizes)
  * authentication: wrong key and tampered frames are rejected, never "decrypted"
  * recovery from lost / inserted / flipped bytes, truncated frames, silence
  * a decoy header in front of a good frame (regression for a real bug)
  * serial reconnect and output-port handling
  * a seeded fuzz test with random error injection: no garbled telegram may
    ever be delivered and no undamaged frame may ever be lost
"""
import argparse
import os
import random
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import serial  # noqa: E402
from Cryptodome.Cipher import AES  # noqa: E402

import decrypt  # noqa: E402

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
AAD = bytes.fromhex("3000112233445566778899AABBCCDDEEFF")
TITLE = b"SAG12345"


# --------------------------------------------------------------------------
# Helpers: telegrams, frames, fake serial connection, fake clock
# --------------------------------------------------------------------------
def crc16(data):
    """DSMR CRC16 (poly 0xA001, init 0) over everything from '/' up to and including '!'."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def make_telegram(rng):
    body = b"/XMX5LGF0010453842839\r\n\r\n"
    for _ in range(rng.randint(8, 18)):
        body += "1-0:{}.{}.0({:08d}*kWh)\r\n".format(
            rng.randint(1, 99), rng.randint(0, 9), rng.randint(0, 10 ** 8)).encode()
    body += b"!"
    return body + "{:04X}\r\n".format(crc16(body)).encode()


def crc_ok(msg):
    b = msg.encode("utf-8", "replace")
    i = b.rfind(b"!")
    try:
        return i > 0 and int(b[i + 1:i + 5], 16) == crc16(b[:i + 1])
    except ValueError:
        return False


def make_frame(counter, text, key=KEY, aad=AAD, title=TITLE):
    """Build one encrypted DLMS frame exactly as the meter sends it."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=title + counter.to_bytes(4, "big"), mac_len=12)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(text)
    length = 1 + 4 + len(ct) + 12
    return (bytes([0xDB, len(title)]) + title + b"\x82" + length.to_bytes(2, "big") +
            b"\x21" + counter.to_bytes(4, "big") + ct + tag)


class StreamEnd(BaseException):
    """Raised by the fake connection when the scripted stream is exhausted."""


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class FakeConn:
    """Scripted serial input. `items` is a list of byte strings (data bursts)
    or None (one read timeout = 1 s of silence)."""

    def __init__(self, items, clock, rng=None, chunk=None):
        self.items = list(items)
        self.cur = b""
        self.clock = clock
        self.rng = rng or random.Random(0)
        self.chunk = chunk
        self.closed = False

    @property
    def in_waiting(self):
        return self.chunk if self.chunk else self.rng.randint(0, 64)

    def read(self, n=1):
        while not self.cur:
            if not self.items:
                raise StreamEnd()
            item = self.items.pop(0)
            if item is None:
                self.clock.now += 1.0
                return b""
            self.cur = item
        out, self.cur = self.cur[:n], self.cur[n:]
        return out

    def close(self):
        self.closed = True


def make_proxy(callback, key=KEY, aad=AAD, output_port=None):
    p = decrypt.SmartyProxy()
    p._args = argparse.Namespace(key=key.hex(), aad=aad.hex(), parse=False,
                                 serial_output_port=output_port, serial_input_port="fake")
    p._key, p._aad = key, aad
    p._callback = callback
    return p


def run_stream(items, key=KEY, chunk=None, seed=0):
    """Feed `items` through a SmartyProxy. Returns (telegrams, errors, frame_counters)."""
    telegrams, errors, counters = [], [], []

    def cb(fc, t, e):
        if fc:
            counters.append(fc)
        if t:
            telegrams.append(t)
        if e:
            errors.append(e)

    clock = Clock()
    proxy = make_proxy(cb, key=key)
    proxy._connection = FakeConn(items, clock, random.Random(seed), chunk)
    with mock.patch.object(decrypt.time, "monotonic", clock):
        try:
            while True:
                proxy.process()
        except StreamEnd:
            pass
    return telegrams, errors, counters


def texts_and_frames(n, seed=1, start=0):
    rng = random.Random(seed)
    texts = [make_telegram(rng) for _ in range(n)]
    frames = [make_frame(start + i, t) for i, t in enumerate(texts)]
    return texts, frames


# --------------------------------------------------------------------------
# Basic behaviour
# --------------------------------------------------------------------------
class TestNormalOperation(unittest.TestCase):
    def test_clean_stream_is_delivered_in_order(self):
        texts, frames = texts_and_frames(10)
        got, errors, _ = run_stream([b"".join(frames)])
        self.assertEqual(got, [t.decode() for t in texts])
        self.assertEqual(errors, [])
        self.assertTrue(all(crc_ok(m) for m in got))

    def test_leading_garbage_is_ignored(self):
        texts, frames = texts_and_frames(3)
        got, _, _ = run_stream([b"\x00\x11\x22\x33" + b"".join(frames)])
        self.assertEqual(got, [t.decode() for t in texts])

    def test_any_chunk_size_works(self):
        texts, frames = texts_and_frames(5)
        stream = b"".join(frames)
        for chunk in (1, 2, 7, 64, 100000):
            with self.subTest(chunk=chunk):
                got, errors, _ = run_stream([stream], chunk=chunk)
                self.assertEqual(got, [t.decode() for t in texts])
                self.assertEqual(errors, [])

    def test_frame_counter_is_reported_as_hex(self):
        _, frames = texts_and_frames(1, start=0x01020304)
        _, _, counters = run_stream(frames)
        self.assertEqual(counters, [b"01020304"])

    def test_frames_separated_by_silence(self):
        texts, frames = texts_and_frames(4)
        items = []
        for f in frames:
            items += [f] + [None] * 10
        got, errors, _ = run_stream(items)
        self.assertEqual(got, [t.decode() for t in texts])
        self.assertEqual(errors, [])


# --------------------------------------------------------------------------
# Authentication: nothing unauthenticated may ever be delivered
# --------------------------------------------------------------------------
class TestAuthentication(unittest.TestCase):
    def test_wrong_key_delivers_nothing(self):
        _, frames = texts_and_frames(3)
        got, errors, _ = run_stream(frames, key=bytes(16))
        self.assertEqual(got, [])
        self.assertEqual(len(errors), 3)
        self.assertTrue(all("Invalid Tag" in e for e in errors))

    def test_flipped_ciphertext_bit_is_rejected_not_garbled(self):
        texts, frames = texts_and_frames(3)
        bad = bytearray(frames[1])
        bad[40] ^= 0x01
        got, errors, _ = run_stream([frames[0] + bytes(bad) + frames[2]])
        self.assertEqual(got, [texts[0].decode(), texts[2].decode()])
        self.assertEqual(len(errors), 1)

    def test_flipped_tag_bit_is_rejected(self):
        texts, frames = texts_and_frames(3)
        bad = bytearray(frames[1])
        bad[-1] ^= 0x80
        got, _, _ = run_stream([frames[0] + bytes(bad) + frames[2]])
        self.assertEqual(got, [texts[0].decode(), texts[2].decode()])

    def test_wrong_aad_delivers_nothing(self):
        text = make_telegram(random.Random(3))
        frame = make_frame(0, text, aad=bytes.fromhex("30" + "11" * 16))
        got, errors, _ = run_stream([frame])
        self.assertEqual(got, [])
        self.assertEqual(len(errors), 1)


# --------------------------------------------------------------------------
# Recovery from transmission errors
# --------------------------------------------------------------------------
class TestRecovery(unittest.TestCase):
    def check_only_damaged_lost(self, frames, texts, damaged, items=None):
        got, _, _ = run_stream(items if items is not None else [b"".join(frames)])
        expected = [t.decode() for i, t in enumerate(texts) if i not in damaged]
        self.assertEqual(got, expected)

    def test_lost_byte_back_to_back(self):
        texts, frames = texts_and_frames(8)
        frames[3] = frames[3][:40] + frames[3][41:]
        self.check_only_damaged_lost(frames, texts, {3})

    def test_inserted_bytes_back_to_back(self):
        texts, frames = texts_and_frames(8)
        frames[4] = frames[4][:30] + b"\x55\xAA" + frames[4][30:]
        self.check_only_damaged_lost(frames, texts, {4})

    def test_truncated_frame_back_to_back(self):
        texts, frames = texts_and_frames(8)
        frames[2] = frames[2][:100]
        self.check_only_damaged_lost(frames, texts, {2})

    def test_truncated_frame_then_silence(self):
        texts, frames = texts_and_frames(5)
        frames[1] = frames[1][:100]
        items = []
        for f in frames:
            items += [f] + [None] * 10
        self.check_only_damaged_lost(frames, texts, {1}, items)

    def test_corrupted_header_bytes(self):
        texts, frames = texts_and_frames(6)
        for offset in (0, 1, 2 + len(TITLE), 3 + len(TITLE), 4 + len(TITLE)):
            with self.subTest(offset=offset):
                broken = list(frames)
                b = bytearray(broken[2])
                b[offset] ^= 0xFF
                broken[2] = bytes(b)
                self.check_only_damaged_lost(broken, texts, {2})

    def test_garbage_burst_between_frames(self):
        texts, frames = texts_and_frames(4)
        rng = random.Random(9)
        junk = bytes(rng.randrange(256) for _ in range(500)) + b"\xdb" * 20
        got, _, _ = run_stream([frames[0] + junk + frames[1] + junk + frames[2] + frames[3]])
        self.assertEqual(got, [t.decode() for t in texts])

    def test_decoy_header_in_front_of_good_frame_back_to_back(self):
        """A false start whose length field claims 1500 bytes must not swallow
        the good frames behind it. Delivery of those frames is delayed until
        the claimed length has arrived (or the line goes quiet), so the stream
        is long enough to cover it; nothing may be lost."""
        texts, frames = texts_and_frames(12)
        decoy = b"\xdb\x08" + bytes(range(8)) + b"\x82" + (1500).to_bytes(2, "big") + b"\x01\x02"
        got, _, _ = run_stream([decoy + b"".join(frames)])
        self.assertEqual(got, [t.decode() for t in texts])

    def test_decoy_header_followed_by_good_frames_then_silence(self):
        """Same decoy, but the stream ends early: the silence timeout must
        release the frames that were waiting behind it."""
        texts, frames = texts_and_frames(3)
        decoy = b"\xdb\x08" + bytes(range(8)) + b"\x82" + (1500).to_bytes(2, "big") + b"\x01\x02"
        got, _, _ = run_stream([decoy + b"".join(frames)] + [None] * 10)
        self.assertEqual(got, [t.decode() for t in texts])

    def test_decoy_header_in_front_of_good_frame_then_silence(self):
        """Regression: the stale-buffer timeout used to throw the good frame
        away together with the decoy."""
        texts, frames = texts_and_frames(3)
        decoy = b"\xdb\x08" + bytes(range(8)) + b"\x82" + (1500).to_bytes(2, "big") + b"\x01\x02"
        items = [decoy + frames[0]] + [None] * 10 + [frames[1]] + [None] * 10 + [frames[2]]
        got, _, _ = run_stream(items)
        self.assertEqual(got, [t.decode() for t in texts])

    def test_implausible_lengths_are_skipped(self):
        texts, frames = texts_and_frames(2)
        for bad_len in (0, 5, 16, 3000, 65535):
            with self.subTest(length=bad_len):
                fake = b"\xdb\x08" + TITLE + b"\x82" + bad_len.to_bytes(2, "big") + b"\x21" * 30
                got, _, _ = run_stream([fake + b"".join(frames)])
                self.assertEqual(got, [t.decode() for t in texts])

    def test_no_data_means_no_output_and_no_crash(self):
        got, errors, _ = run_stream([None] * 20)
        self.assertEqual((got, errors), ([], []))


# --------------------------------------------------------------------------
# Serial port handling
# --------------------------------------------------------------------------
class FakeOutPort:
    """Stand-in for serial.Serial on the output side."""
    instances = []
    fail_on_write = set()      # 1-based write numbers (over all instances) that raise

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.writes = []
        self.closed = False
        FakeOutPort.instances.append(self)

    def write(self, data):
        n = sum(len(i.writes) for i in FakeOutPort.instances) + 1
        if n in FakeOutPort.fail_on_write:
            FakeOutPort.fail_on_write.discard(n)
            raise serial.SerialException("write failed")
        self.writes.append(bytes(data))

    def flush(self):
        pass

    def close(self):
        self.closed = True


class TestSerialHandling(unittest.TestCase):
    def setUp(self):
        FakeOutPort.instances = []
        FakeOutPort.fail_on_write = set()

    def test_output_port_is_opened_once_and_reused(self):
        errors = []
        proxy = make_proxy(lambda fc, t, e: errors.append(e) if e else None, output_port="/dev/pts/9")
        with mock.patch.object(decrypt.serial, "Serial", FakeOutPort):
            for i in range(3):
                proxy.write_to_serial_port(b"telegram%d" % i)
        self.assertEqual(len(FakeOutPort.instances), 1)
        self.assertEqual(FakeOutPort.instances[0].writes, [b"telegram0", b"telegram1", b"telegram2"])
        self.assertEqual(errors, [])
        self.assertIn("write_timeout", FakeOutPort.instances[0].kwargs)

    def test_output_port_is_reopened_after_write_error(self):
        errors = []
        proxy = make_proxy(lambda fc, t, e: errors.append(e) if e else None, output_port="/dev/pts/9")
        FakeOutPort.fail_on_write = {2}
        with mock.patch.object(decrypt.serial, "Serial", FakeOutPort):
            proxy.write_to_serial_port(b"one")
            proxy.write_to_serial_port(b"two")     # fails, port is closed and dropped
            proxy.write_to_serial_port(b"three")   # reopens and succeeds
        self.assertEqual(len(FakeOutPort.instances), 2)
        self.assertTrue(FakeOutPort.instances[0].closed)
        self.assertEqual(FakeOutPort.instances[1].writes, [b"three"])
        self.assertEqual(len(errors), 1)

    def test_output_port_failure_does_not_kill_the_reader(self):
        """A dead output port must not stop telegrams being processed."""
        texts, frames = texts_and_frames(3)
        got = []
        clock = Clock()
        proxy = make_proxy(lambda fc, t, e: got.append(t) if t else None, output_port="/dev/pts/9")
        proxy._connection = FakeConn([b"".join(frames)], clock)
        with mock.patch.object(decrypt.serial, "Serial", side_effect=serial.SerialException("gone")), \
                mock.patch.object(decrypt.time, "monotonic", clock):
            try:
                while True:
                    proxy.process()
            except StreamEnd:
                pass
        self.assertEqual(got, [t.decode() for t in texts])

    def test_input_port_reconnects_after_failure(self):
        texts, frames = texts_and_frames(3)
        clock = Clock()
        calls = []

        def factory(*args, **kwargs):
            calls.append(kwargs)
            if len(calls) == 1:
                raise serial.SerialException("device not ready")
            return FakeConn([b"".join(frames)], clock)

        got, errors = [], []
        proxy = decrypt.SmartyProxy()
        cmdline = [KEY.hex(), "-a", AAD.hex(), "-i", "fake"]
        cb = lambda fc, t, e: (got.append(t) if t else None, errors.append(e) if e else None)  # noqa: E731
        with mock.patch.object(decrypt.serial, "Serial", factory), \
                mock.patch.object(decrypt.time, "sleep"), \
                mock.patch.object(decrypt.time, "monotonic", clock):
            with self.assertRaises(StreamEnd):
                proxy.main(cmdline, cb)
        self.assertEqual(len(calls), 2)
        self.assertEqual(got, [t.decode() for t in texts])
        self.assertTrue(any("Serial error" in e for e in errors))
        self.assertEqual(calls[1].get("timeout"), decrypt.SmartyProxy.READ_TIMEOUT)

    def test_input_port_reconnects_after_read_error(self):
        texts, frames = texts_and_frames(2)
        clock = Clock()

        class DyingConn(FakeConn):
            def read(self, n=1):
                raise serial.SerialException("usb unplugged")

        conns = [DyingConn([], clock), FakeConn([b"".join(frames)], clock)]
        got = []
        proxy = decrypt.SmartyProxy()
        with mock.patch.object(decrypt.serial, "Serial", lambda *a, **k: conns.pop(0)), \
                mock.patch.object(decrypt.time, "sleep"), \
                mock.patch.object(decrypt.time, "monotonic", clock):
            with self.assertRaises(StreamEnd):
                proxy.main([KEY.hex(), "-a", AAD.hex()], lambda fc, t, e: got.append(t) if t else None)
        self.assertEqual(got, [t.decode() for t in texts])


# --------------------------------------------------------------------------
# Fuzzing with random error injection
# --------------------------------------------------------------------------
def damage(rng, frame):
    f = bytearray(frame)
    kind = rng.choice(["flip", "drop", "insert", "truncate", "header"])
    if kind == "flip":
        for _ in range(rng.randint(1, 3)):
            f[rng.randrange(len(f))] ^= rng.randint(1, 255)
    elif kind == "drop":
        i = rng.randrange(len(f))
        del f[i:i + rng.randint(1, 3)]
    elif kind == "insert":
        i = rng.randrange(len(f))
        f[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 3)))
    elif kind == "truncate":
        del f[rng.randint(5, len(f) - 1):]
    else:
        f[rng.randrange(0, 9)] ^= rng.randint(1, 255)
    return bytes(f)


def noise(rng):
    kind = rng.choice(["random", "dbs", "decoy"])
    if kind == "random":
        return bytes(rng.randrange(256) for _ in range(rng.randint(1, 300)))
    if kind == "dbs":
        return b"\xdb" * rng.randint(1, 50)
    return (b"\xdb\x08" + bytes(rng.randrange(256) for _ in range(8)) + b"\x82" +
            rng.randint(800, 2000).to_bytes(2, "big") + bytes(rng.randrange(256) for _ in range(rng.randint(0, 100))))


def build_fuzz_stream(seed, n, p, gaps):
    rng = random.Random(seed)
    items, texts, clean = [], [], []
    for i in range(n + 10):                      # 10 clean tail frames flush any pending state
        text = make_telegram(rng)
        texts.append(text)
        frame = make_frame(i, text)
        damaged = i < n and rng.random() < p
        if damaged:
            frame = damage(rng, frame)
        prefix = noise(rng) if (i < n and rng.random() < p / 2) else b""
        items.append(prefix + frame)
        if gaps:
            items.extend([None] * 10)            # 10 s of silence between telegrams
        clean.append(not damaged)
    return items, texts, clean


class TestFuzz(unittest.TestCase):
    N = 300
    SEEDS = (1, 2, 3)
    RATES = (0.02, 0.10, 0.30)

    def run_fuzz(self, gaps):
        for p in self.RATES:
            for seed in self.SEEDS:
                with self.subTest(gaps=gaps, p=p, seed=seed):
                    items, texts, clean = build_fuzz_stream(seed, self.N, p, gaps)
                    got, _, _ = run_stream(items, seed=seed)
                    index = {t.decode(): i for i, t in enumerate(texts)}

                    garbled = [m for m in got if m not in index]
                    self.assertEqual(garbled, [], "garbled telegram delivered")
                    bad_crc = [m for m in got if not crc_ok(m)]
                    self.assertEqual(bad_crc, [], "telegram with bad CRC delivered")

                    delivered = {index[m] for m in got}
                    lost = [i for i in range(self.N) if clean[i] and i not in delivered]
                    self.assertEqual(lost, [], "undamaged frames were lost")

    def test_fuzz_back_to_back(self):
        self.run_fuzz(gaps=False)

    def test_fuzz_with_gaps_between_telegrams(self):
        self.run_fuzz(gaps=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
