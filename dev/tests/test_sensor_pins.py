"""Sensor certificate pinning (trust on first use): the check runs after the handshake and before any request."""
import datetime
import os
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sensorops import pins  # noqa: E402 - sys.path is set first
try:
    from sensorops.providers.network_sensor import NetworkSensorProvider  # noqa: E402 - sys.path is set first
except ImportError:                                  # public builds do not ship the vendor connector
    NetworkSensorProvider = None


def make_cert(dirname, name):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    cf, kf = os.path.join(dirname, name + ".crt"), os.path.join(dirname, name + ".key")
    with open(cf, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kf, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return cf, kf


class TLSServer:
    def __init__(self, cert, key):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.requests = []
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            try:
                c, _ = self.sock.accept()
                t = self.ctx.wrap_socket(c, server_side=True)
                self.requests.append(t.recv(100))
                t.close()
            except (OSError, ssl.SSLError):
                if self.sock.fileno() < 0:
                    return

    def close(self):
        self.sock.close()


@unittest.skipIf(NetworkSensorProvider is None, "the sensor connector is not installed")
class Pinning(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        p = mock.patch.dict(os.environ, {"OG_SETTINGS_DIR": self.tmp})
        p.start()
        self.addCleanup(p.stop)

    def connect(self, srv, sensor="lab.example.net"):
        ctx = NetworkSensorProvider(sensor, "K")._ctx()
        with socket.create_connection(("127.0.0.1", srv.port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=None) as tls:
                tls.sendall(b"SECRET-API-KEY")

    def test_first_use_pins_then_same_cert_passes_and_a_changed_cert_is_refused_before_sending(self):
        a = TLSServer(*make_cert(self.tmp, "a"))
        b = TLSServer(*make_cert(self.tmp, "b"))
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        self.connect(a)                                         # first contact pins
        self.connect(a)                                         # same cert
        with self.assertRaises(ssl.SSLError) as c:
            self.connect(b)                                     # another cert for the same sensor
        self.assertIn("Nothing was sent", str(c.exception))
        self.assertEqual(b.requests, [])                        # the key never reached the impostor
        self.connect(b, "other.example.net")                    # pins are per sensor
        mode = os.stat(os.path.join(self.tmp, pins.PIN_FILE)).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_the_pin_file_is_read_back_and_bad_entries_are_ignored(self):
        pins.check("S.example.net", "a" * 64)
        with self.assertRaises(ssl.SSLError):
            pins.check("s.example.net", "b" * 64)               # sensor names compare case-insensitively
        with open(os.path.join(self.tmp, pins.PIN_FILE), "w") as fh:
            fh.write('{"s.example.net": "not-hex", "t": 5}')
        pins.check("s.example.net", "b" * 64)                   # a corrupt entry is replaced, not trusted


if __name__ == "__main__":
    unittest.main()
