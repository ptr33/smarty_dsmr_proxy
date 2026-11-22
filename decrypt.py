import argparse
import binascii
import time

import serial
from Cryptodome.Cipher import AES

has_dsmr_parser = True
try:
    from dsmr_parser import telegram_specifications
    from dsmr_parser.parsers import TelegramParser
except ImportError:
    has_dsmr_parser = False


class SmartyProxy():
    """Decrypts DLMS/COSEM (security suite 0) frames from a Smarty/Sagemcom meter.

    Frame layout (all offsets in bytes):
        0            0xDB (general-glo-ciphering)
        1            system title length (normally 8)
        2 .. 2+stl   system title
        2+stl        0x82
        3+stl .. 4+stl   length L of everything that follows (big endian)
        5+stl        security byte (0x21)
        6+stl .. 9+stl   frame counter (4 bytes)
        ...          ciphertext (L - 17 bytes)
        last 12      GCM tag
    Total frame length = 5 + stl + L.

    Compared to the old byte-by-byte state machine this version:
      * buffers input and resynchronises on the next start byte whenever a
        frame is invalid, instead of silently swallowing following frames,
      * verifies the GCM tag (the old code never did, so corrupted frames
        were "decrypted" to garbage and then failed the DSMR CRC check),
      * drops partial frames after a read timeout,
      * reconnects the serial ports after errors instead of giving up.
    """

    START_BYTE = 0xDB
    SEPARATOR = 0x82
    TAG_LEN = 12
    MAX_DATA_LENGTH = 2048     # sanity limit for the length field
    READ_TIMEOUT = 1.0         # seconds
    STALE_AFTER = 3.0          # drop a partial frame if no data arrives for this long
    RECONNECT_DELAY = 2.0      # seconds

    def __init__(self):
        self._args = None
        self._callback = None
        self._connection = None   # serial input (smart meter)
        self._out = None          # serial output (e.g. socat pty), kept open
        self._buf = bytearray()
        self._last_rx = time.monotonic()
        self._key = b""
        self._aad = b""
        self._parser = None

    # ------------------------------------------------------------------ setup
    def main(self, cmdline=None, callback=None):
        parser = argparse.ArgumentParser()
        parser.add_argument('key', help="Decryption key")
        parser.add_argument('-i', '--serial-input-port', required=False, default="/dev/ttyUSB0", help="Input port. Defaults to /dev/ttyUSB0.")
        parser.add_argument('-o', '--serial-output-port', required=False, help="Output port, e.g. /dev/pts/2.")
        parser.add_argument('-a', '--aad', required=False, default="3000112233445566778899AABBCCDDEEFF", help="Additional authenticated data")
        parser.add_argument('-p', '--parse', action='store_true', required=False, default=False, help="Parse and pretty print DSMR v5 telegram")
        if cmdline:
            self._args = parser.parse_args(cmdline)
        else:
            self._args = parser.parse_args()
        # callback for processing of received data
        # this will be called with dsmr_parser telegram if dsmr_parser is installed and -p option is used
        # otherwise with string of the received message
        #   callback(framecounter, dsmr_parser.telegram or text, error)
        self._callback = callback

        self._key = binascii.unhexlify(self._args.key)
        self._aad = binascii.unhexlify(self._args.aad)
        if has_dsmr_parser and self._args.parse:
            self._parser = TelegramParser(telegram_specifications.V5)

        while True:
            try:
                self.process()
            except (serial.SerialException, OSError) as err:
                self._report(f'Serial error {err!r}, reconnecting in {self.RECONNECT_DELAY}s')
                self._close_input()
                self._buf.clear()
                time.sleep(self.RECONNECT_DELAY)

    def connect(self):
        self._connection = serial.Serial(
            port=self._args.serial_input_port,
            baudrate=115200,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=self.READ_TIMEOUT,
        )
        self._buf.clear()
        self._last_rx = time.monotonic()

    def _close_input(self):
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
        self._connection = None

    def _report(self, msg):
        if self._callback:
            self._callback(None, None, msg)
        else:
            print(msg)

    # ------------------------------------------------------------- read loop
    def process(self):
        """One iteration of the read loop. Serial errors propagate to main()."""
        if self._connection is None:
            self.connect()

        chunk = self._connection.read(max(1, self._connection.in_waiting))
        now = time.monotonic()
        if chunk:
            self._buf.extend(chunk)
            self._last_rx = now
        elif self._buf and now - self._last_rx > self.STALE_AFTER:
            # Half a frame and then silence: the rest was lost. Give up on the
            # pending start byte, but rescan what is behind it: a complete,
            # valid frame may be hiding there (e.g. after a false start byte
            # whose length field claimed more data than ever arrived).
            self._report('WARNING: incomplete frame timed out, resynchronising')
            while self._buf:
                del self._buf[:1]
                self._extract_frames()
            return

        self._extract_frames()

    def _extract_frames(self):
        buf = self._buf
        while True:
            start = buf.find(bytes([self.START_BYTE]))
            if start < 0:
                buf.clear()
                return
            if start > 0:
                del buf[:start]

            if len(buf) < 2:
                return
            stl = buf[1]
            if stl == 0 or stl > 16:
                del buf[:1]            # not a plausible header, resync
                continue

            header_len = 2 + stl + 3   # start, stl, system title, 0x82, 2 length bytes
            if len(buf) < header_len:
                return
            if buf[2 + stl] != self.SEPARATOR:
                del buf[:1]
                continue

            data_length = (buf[3 + stl] << 8) | buf[4 + stl]
            # security byte (1) + frame counter (4) + tag (12) = 17 bytes minimum
            if data_length < 1 + 4 + self.TAG_LEN or data_length > self.MAX_DATA_LENGTH:
                del buf[:1]
                continue

            total = 5 + stl + data_length
            if len(buf) < total:
                return                 # wait for more data

            frame = bytes(buf[:total])
            if self._handle_frame(frame, stl):
                del buf[:total]
            else:
                # Invalid frame: it may have been a false start byte inside
                # garbage, so only skip one byte and look for the next 0xDB.
                del buf[:1]

    # ------------------------------------------------------------ one frame
    def _handle_frame(self, frame, stl):
        system_title = frame[2:2 + stl]
        body = frame[5 + stl:]
        frame_counter = body[1:5]
        payload = body[5:-self.TAG_LEN]
        gcm_tag = body[-self.TAG_LEN:]

        try:
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=system_title + frame_counter, mac_len=self.TAG_LEN)
            cipher.update(self._aad)
            decryption = cipher.decrypt_and_verify(payload, gcm_tag)
        except ValueError:
            self._report('ERROR: Invalid Tag (corrupt frame or wrong key/AAD), dropping frame')
            return False

        counter_hex = binascii.hexlify(frame_counter)
        if self._callback:
            self._callback(counter_hex, None, None)
        else:
            print("Framecounter")
            print(counter_hex)

        self._deliver(decryption)

        if self._args.serial_output_port:
            self.write_to_serial_port(decryption)
        return True

    def _deliver(self, decryption):
        msg = decryption.decode('utf-8', errors='replace')
        if self._parser is not None:
            try:
                telegram = self._parser.parse(msg)
                if self._callback:
                    self._callback(None, telegram, None)
                else:
                    print(telegram)
            except Exception as e:
                self._report("ERROR: Cannot parse DSMR Telegram" + repr(e) + "\n" + msg)
        else:
            if self._callback:
                self._callback(None, msg, None)
            else:
                print(msg)

    # --------------------------------------------------------------- output
    def write_to_serial_port(self, decryption):
        """Write to the output port (e.g. a socat pty). The port is kept open
        between telegrams and re-opened after any error."""
        try:
            if self._out is None:
                self._out = serial.Serial(
                    port=self._args.serial_output_port,
                    baudrate=115200,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE,
                    write_timeout=2,
                )
            self._out.write(decryption)
            self._out.flush()
        except (serial.SerialException, OSError) as err:
            self._report(f'Output port error {err!r}, will retry on next telegram')
            try:
                if self._out is not None:
                    self._out.close()
            except Exception:
                pass
            self._out = None


if __name__ == '__main__':
    smarty_proxy = SmartyProxy()
    smarty_proxy.main()
