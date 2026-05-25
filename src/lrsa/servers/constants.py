"""Local capture and relay server defaults."""

from pathlib import Path

REAL_BASE = "https://lsa.lenovo.com"
HTTP_RELAY_PORT = 9999
HTTPS_RELAY_PORT = 9443
CAPTURE_PORT = 443
HOSTS_FILE = "/etc/hosts"
DEFAULT_CAPTURE_HOSTS = ("lsa.lenovo.com",)
CERT_FILE = "/tmp/lsa_cert.pem"
KEY_FILE = "/tmp/lsa_key.pem"
HTTPS_RELAY_CERT_FILE = "/tmp/relay_cert.pem"
HTTPS_RELAY_KEY_FILE = "/tmp/relay_key.pem"
HTTPS_RELAY_LOG_FILE = "/tmp/relay_traffic.log"
DEFAULT_OUT_DIR = Path("lrsa_work/capture")
FORWARD_TIMEOUT = 30
