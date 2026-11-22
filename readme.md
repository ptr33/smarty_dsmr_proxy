# Decrypter and proxy for Luxembourgish "Smarty" meters

This piece of code acts as a "proxy" between the Luxembourgish "Smarty" meters and existing open source software that analyse DSMR telegrams. E.g. [dsmr_parser](https://github.com/ndokter/dsmr_parser).

I run this on a Linux PC that I have connected to my "Smarty" meter using a serial-to-USB cable.

This version decrypts the **dlms/COSEM-Security 0** which is used in Austria for the Sagemcom smart meters.

This version supports using decrypt.py as a library with a callback, which is called whenever a new message is available.

## Before you start

- Ask you energy provider for your decryption key. This might take a few days. You might want to request from LuxMetering the activation of the full read-out on your smart-meter if you want to get instant voltage/current readings per phase.
- You need a cable to connect your Raspberry Pi (or whatever else you want to use) to the "P1 port" of your smart meter. Those cables are available under different names: "DSMR cable", "P1 cable" or "slimme meter kabel" (which is Dutch for "smart meter cable").
- You need to install the "pycryptodomex" and "pyserial" libraries for Python: `pip install pycryptodomex pyserial` (Ubuntu/Debian: `sudo apt-get install python3-pycryptodomex python3-serial`). The "cryptography" library is no longer needed.
- You might need to install "socat" for the examples below. Ubuntu/Debian: `sudo apt-get install socat`

## Test if everything works

- Run the following on the command line and watch the telegrams appear on screen: `python3 decrypt.py KEY` (with "KEY" being your decryption key)
- If the serial-to-usb cable is not accessible under /dev/ttyUSB0, you can use the "--serial-input-port" argument to specify which path to read from.
- Push CTRL+C to exit

## Option 1: Use it as a library

Install library dsmr_parser and AES decryption:

```
pip install dsmr_parser pycryptodomex
```

Following python script can be used to readout and process the data

```
import sys
import dsmr_parser
# change to path where you have stored decrypt.py
sys.path.append('/notebooks/smartmeter/smarty_dsmr_proxy')
import decrypt


# this function gets called whenever a new message is available
def callback(framecounter, telegram, error):
    # only one if condition will be true for every call
    if error:         # there was en error
        print(f'Error {error}')
    if framecounter:  # framecounter received
        print(f'Framecounter {framecounter}')
    if telegram:      # dsmr_telegram received, pretty print it
        # pretty print whole message
        print(f'Telegram {telegram}')
        # simple access to individual items - see https://github.com/ndokter/dsmr_parser
        print(f'Electricity usage: {telegram.CURRENT_ELECTRICITY_USAGE.value} {telegram.CURRENT_ELECTRICITY_USAGE.unit}')


smarty_proxy = decrypt.SmartyProxy()
# start infinite readout loop - provide configurations parameters: -p for processing and DECRYPTION_KEY
smarty_proxy.main(['-p', DECRYPTION_KEY], callback)
```

Errors and warnings are delivered through the `error` argument of the callback (for example `ERROR: Invalid Tag ...`, `Serial error ...` or `WARNING: incomplete frame timed out ...`). Without a callback they are printed to the console instead.

## Option 2: Connect your smart meter to dsmr_parser (or a Home Assistant instance) that runs remotely

Start socat to get a virtual serial port that is forwarded to a TCP connection on port 2001. **Please be aware that this way, the data from your smart meter is available unencrypted on your network!**

```
socat -d -d pty,raw,echo=0 TCP-LISTEN:2001,reuseaddr
```

The output should look as follows.

```
2018/04/13 20:30:00 socat[1301] N PTY is /dev/pts/2
2018/04/13 20:30:00 socat[1301] N listening on AF=2 0.0.0.0:2001
(...)
```

Using the given port name, you can now start the proxy with the "--serial-output-port" argument (with the port name from the previous output).

```
python3 decrypt.py KEY --serial-output-port=/dev/pts/2
```

You can now configure dsmr_parser (or your Home Assistant instance) to use a TCP connection to the current device on port 2001.

### To connect your smart meter to dsmr_reader, dsmr_parser (or a Home Assistant instance) that runs on the same machine

Start socat to get a virtual serial port that is connected to a second virtual serial port.

```
socat -d -d pty,raw,echo=0 pty,raw,echo=0
```

The output should look as follows.

```
2018/04/13 20:30:00 socat[1301] N PTY is /dev/pts/2
2018/04/13 20:30:00 socat[1301] N PTY is /dev/pts/3
(...)
```

Using the given port name, you can now start the proxy with the "--serial-output-port" argument (with the first port name from the previous output).

```
python3 decrypt.py KEY --serial-output-port=/dev/pts/2
```

You can now configure dsmr_reader, dsmr_parser (or your Home Assistant instance) to connect to the second port from the previous output (in this example /dev/pts/3).

### Make everything start up automatically

There are different ways to achieve this. One of the easiest is to install "supervisord":

```
sudo apt-get install supervisor
```

Then create a custom configuration:

```
sudo nano /etc/supervisor/conf.d/smarty_dsmr_proxy.conf
```

My configuration looks like this. Don't forget to use your individual decryption key. To cope with the changing pts numbers, it is easiest to use the "link=" option of socat to create a symbolic name with a fixed name (if you want this link in /dev, socat will have to run as root, and you may need to use the "group=" and "mode=" options of socat so that the proxy can still write on the pts). If you use a second pts as local end point, you can use the same option on the second 'pty' block to provide a fixed name for this as well:

```
[program:socat]
command=socat -d -d pty,raw,echo=0,link=/home/pi/smarty_proxy_pts TCP-LISTEN:2001,reuseaddr
priority=10
autostart=true
autorestart=true
user=pi

[program:smarty_dsmr_proxy]
command=python3 /home/pi/smarty_dsmr_proxy/decrypt.py DECRYPTION_KEY --serial-output-port=/home/pi/smarty_proxy_pts
priority=20
autostart=true
autorestart=true
user=pi
```

And then start it (or simply restart your device):

```
sudo service supervisor restart
```

## Robustness: how errors are handled

Serial lines are not perfect (long P1 cables, cheap USB adapters, electrical noise), so the proxy is built to survive damaged data instead of passing it on:

- **Every frame is authenticated.** The AES-GCM tag of each frame is verified. A frame that fails verification is dropped and reported as `Invalid Tag`; it is never decrypted into garbage and handed to dsmr_parser, which used to show up as CRC errors.
- **Frames are read by their length field** and the reader resynchronises on the next start byte (`0xDB`) after any invalid frame, so one damaged frame no longer takes the following frames with it.
- **Partial frames time out.** If a frame is cut off and the line then stays quiet for about 3 seconds, the pending data is given up (frames that arrived behind it are still processed).
- **The input port reconnects.** After a serial error the port is closed and reopened every 2 seconds until the device is back.
- **The output port is kept open** between telegrams (instead of being opened and closed for every telegram), uses a write timeout so a stuck reader cannot block the proxy, and is reopened after a write error.

### Troubleshooting

- A few `Invalid Tag` messages now and then are normal on a noisy line; the affected telegram is skipped and the next one is processed. Frequent errors point to the cable, the USB adapter or electrical interference.
- `Invalid Tag` for **every** frame means the decryption key (or the additional authenticated data given with `--aad`) is wrong.
- If dsmr_parser still reports CRC errors while no `Invalid Tag` errors appear, the decrypted data is intact and the cause is in the parser or the telegram format.
- When running under supervisord, keep `autorestart=true` as a safety net.

## Running the tests

The tests need no serial hardware: the meter is replaced by an in-memory fake connection and time is driven by a fake clock, so the whole suite runs in a few seconds.

```
pip install pycryptodomex pyserial
python3 -m unittest -v test_decrypt        # or: pytest -v test_decrypt.py
```

Run them from the directory that contains `decrypt.py` and `test_decrypt.py`. They cover:

- normal operation (clean streams, leading garbage, any read chunk size, frame counter)
- authentication (wrong key, wrong AAD and tampered frames must never be delivered)
- recovery from lost, inserted and flipped bytes, truncated frames, corrupted headers, garbage bursts and false start bytes
- serial handling (input reconnect, output port reuse and reopen)
- a seeded fuzz test that injects random errors into an encrypted stream and checks that no garbled or CRC-failing telegram is ever delivered and that no undamaged frame is lost

## Further information

- [DSMR Component for Home Assistant](https://www.home-assistant.io/components/sensor.dsmr/)
- [DSMR Parser](https://github.com/ndokter/dsmr_parser), the library used by Home Assistant to read meter data
- [DSMR Reader](http://dsmr-reader.readthedocs.io/en/latest/), stand-alone utility to log and view your energy consumption
- [P1 Port Specification for Luxembourg's "Smarty" electricity meter](https://smarty.creos.net/wp-content/uploads/P1PortSpecification.pdf), the reference document for this library. It describes how the encryption on top of the DSMR standard works.
