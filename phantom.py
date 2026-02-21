#!/usr/bin/env python3
# Phantom is a secure messaging client for the command line
# Phantom has been made for maximum security and privacy, with end-to-end encryption, a minimal metadata footprint, and a Tor-friendly design
# More info: https://noks.pics/phantom
# U may modify check or do anything u wish with this code
# The code for the relay server is not currently open source
# This client is designed to work with the relay at https://message-server-hzct.onrender.com
# I would only recommend cosmetic modifications to the client code, as the security of your messages depends on it working correctly with the relay

import os, platform, re, shutil, subprocess, sys, importlib, ssl, random
from urllib.parse import urlparse
import mimetypes

RELAY_URL = "https://message-server-hzct.onrender.com"
APP_VERSION = "2.2.3"
APP_CHANGES = """
- Metadata hardening: sender id moved into encrypted message envelope (PHANTOM_MSG_V1)
- Metadata hardening: file uploads now use generic multipart metadata (no local filename leak)
- Improved compatibility: supports both legacy and envelope-based message payloads
""".strip()
UPDATE_URL = "https://noks.pics/phantom.py"
MOTD_URLS = {
    "fun": "https://www.noks.pics/motd/motdfun.txt",
    "privacy": "https://www.noks.pics/motd/motdprivacy.txt",
    "hacker": "https://www.noks.pics/motd/motdhacker.txt",
    "ops": "https://www.noks.pics/motd/motdops.txt",
}
CUSTOM_MOTD_PROFILE = "custom"
DEFAULT_MOTD_PROFILE = "privacy"
UPDATE_CHECK_COOLDOWN_SECONDS = 0

def _ensure_deps():
    checks = {
        "cryptography": "cryptography",
        "requests": "requests",
        "requests-toolbelt": "requests_toolbelt",
        "websocket-client": "websocket",
        "rich": "rich",
    }
    missing = [pkg for pkg, mod in checks.items() if not _can_import(mod)]
    if missing:
        print(f"Installing required packages: {', '.join(missing)}")
        print("This only happens once.\n")
        _install_deps(missing)
        os.execv(sys.executable, [sys.executable] + sys.argv)

def _can_import(mod):
    try:
        importlib.import_module(mod)
        return True
    except ImportError:
        return False

def _install_deps(packages):
    base_cmd = [sys.executable, "-m", "pip", "install", "--quiet", *packages]
    try:
        subprocess.check_call(base_cmd)
        return
    except subprocess.CalledProcessError:
        if os.name != "nt":
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--quiet",
                "--break-system-packages", *packages
            ])
            return
        raise

_ensure_deps()

import time, base64, getpass, hashlib, json, logging, threading, socket, hmac
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography import x509
from cryptography.exceptions import InvalidTag
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import websocket as _ws
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn, TransferSpeedColumn

console = Console()
logging.basicConfig(level=logging.WARNING)
_motd_cache = {"profile": "", "lines": [], "fetched_at": 0}
_motd_current = {"profile": "", "line": ""}

DEFAULT_THEME = "cyan"
THEMES = {
    "cyan": {
        "title": "cyan",
        "panel_border": "cyan",
        "section": "dim",
        "accent": "cyan",
        "cat_border": "magenta",
        "warn_border": "yellow",
        "warn_title": "bold yellow",
        "danger": "bold red",
    },
    "matrix": {
        "title": "green",
        "panel_border": "green",
        "section": "green",
        "accent": "green",
        "cat_border": "green",
        "warn_border": "bright_green",
        "warn_title": "bold bright_green",
        "danger": "bold red",
    },
    "amber": {
        "title": "bright_yellow",
        "panel_border": "yellow",
        "section": "yellow",
        "accent": "yellow",
        "cat_border": "bright_yellow",
        "warn_border": "yellow",
        "warn_title": "bold yellow",
        "danger": "bold red",
    },
    "ocean": {
        "title": "bright_blue",
        "panel_border": "blue",
        "section": "blue",
        "accent": "bright_blue",
        "cat_border": "blue",
        "warn_border": "bright_blue",
        "warn_title": "bold bright_blue",
        "danger": "bold red",
    },
}
CUSTOM_THEME_DEFAULT = {
    "title": "cyan",
    "panel_border": "cyan",
    "section": "dim",
    "accent": "cyan",
    "cat_border": "magenta",
    "warn_border": "yellow",
    "warn_title": "bold yellow",
    "danger": "bold red",
}

def _theme_names():
    return [*list(THEMES.keys()), "custom"]

def _theme_pick(name):
    key = (name or "").strip().lower()
    return key if key in THEMES else DEFAULT_THEME

def _theme_custom_norm(raw):
    out = dict(CUSTOM_THEME_DEFAULT)
    if isinstance(raw, dict):
        for k in out:
            v = raw.get(k)
            if isinstance(v, str) and v.strip():
                out[k] = v.strip()
    return out

def _theme_resolve(theme_name, settings):
    if theme_name == "custom":
        return _theme_custom_norm(settings.get("theme_custom", {}))
    return THEMES.get(theme_name, THEMES[DEFAULT_THEME])

def _motd_profiles():
    return [*list(MOTD_URLS.keys()), CUSTOM_MOTD_PROFILE]

def _motd_profile_pick(name, allow_empty=False):
    key = (name or "").strip().lower()
    if allow_empty and not key:
        return ""
    return key if key in _motd_profiles() else DEFAULT_MOTD_PROFILE

def _motd_custom_norm(raw):
    out = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, str):
                continue
            line = item.strip()
            if line:
                out.append(line)
            if len(out) >= 50:
                break
    return out

def set_terminal_title(title: str):
    system = platform.system()
    if system == "Windows":
        os.system(f"title {title}")
    else:
        sys.stdout.write(f"\033]0;{title}\007")
        sys.stdout.flush()

set_terminal_title(f"Phantom {APP_VERSION}")

CFG_DIR  = Path(os.environ.get("PHANTOM_HOME", str(Path.home() / ".phantom"))).expanduser()
ID_FILE  = CFG_DIR / "identity.json"
CON_FILE = CFG_DIR / "contacts.json"
INIT_FLAG = CFG_DIR / ".initialized"
SET_FILE = CFG_DIR / "settings.json"


# --- crypto ------------------------------------------------------------------

NONCE   = 12
KEYSIZE = 32
SALT_SZ = 32
VER     = b'\x01'
FILE_MSG_PREFIX = "PHANTOM_FILE_V1:"
MSG_ENV_PREFIX = "PHANTOM_MSG_V1:"
FILE_AAD = b"phantom-file-v1"

def _scrypt(password, salt):
    return Scrypt(salt=salt, length=KEYSIZE, n=2**17, r=8, p=1).derive(password.encode())

def gen_keypair():
    enc_priv = X25519PrivateKey.generate()
    sign_priv = Ed25519PrivateKey.generate()
    enc_priv_b = enc_priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    enc_pub_b = enc_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sign_priv_b = sign_priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    sign_pub_b = sign_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return enc_priv_b, enc_pub_b, sign_priv_b, sign_pub_b

def save_identity(path, enc_priv, enc_pub, sign_priv, sign_pub, password):
    salt = os.urandom(SALT_SZ)
    nonce = os.urandom(NONCE)
    ct = ChaCha20Poly1305(_scrypt(password, salt)).encrypt(
        nonce,
        json.dumps({
            "priv": b64e(enc_priv),
            "pub": b64e(enc_pub),
            "sign_priv": b64u_enc(sign_priv),
            "sign_pub": b64u_enc(sign_pub),
        }).encode(),
        b"phantom-v2"
    )
    with open(path, "w") as f:
        json.dump({"salt": b64e(salt), "nonce": b64e(nonce), "ct": b64e(ct)}, f)

def load_identity(path, password):
    with open(path) as f:
        d = json.load(f)
    try:
        pt = ChaCha20Poly1305(_scrypt(password, b64d(d["salt"]))).decrypt(
            b64d(d["nonce"]), b64d(d["ct"]), b"phantom-v2"
        )
    except InvalidTag:
        raise ValueError("Wrong password.")
    d = json.loads(pt)
    sign_priv = b64u_dec(d["sign_priv"]) if d.get("sign_priv") else None
    sign_pub = b64u_dec(d["sign_pub"]) if d.get("sign_pub") else None
    return b64d(d["priv"]), b64d(d["pub"]), sign_priv, sign_pub

def uid_of(pub):
    h = hashlib.sha3_256(b"phantom-uid-v2" + pub).digest()
    return base64.urlsafe_b64encode(h[:21]).decode().rstrip("=")

def room_id_of(my_priv, their_pub):
    # Random-looking stable room id derived from ECDH shared secret (not from UIDs).
    raw = X25519PrivateKey.from_private_bytes(my_priv).exchange(
        X25519PublicKey.from_public_bytes(their_pub)
    )
    rid = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"phantom-room-id-v3",
    ).derive(raw)
    return b64u_enc(rid)

def session_key(my_priv, their_pub, uid_a, uid_b):
    raw = X25519PrivateKey.from_private_bytes(my_priv).exchange(
        X25519PublicKey.from_public_bytes(their_pub)
    )
    return HKDF(
        algorithm=hashes.SHA256(), length=KEYSIZE, salt=None,
        info=b"phantom-session-v2" + "|".join(sorted([uid_a, uid_b])).encode()
    ).derive(raw)

def encrypt(plaintext, key):
    nonce = os.urandom(NONCE)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext.encode(), b"phantom-msg-v2")
    return base64.b64encode(VER + nonce + ct).decode()

def decrypt(ciphertext_b64, key):
    raw = base64.b64decode(ciphertext_b64)
    if raw[:1] != VER:
        raise ValueError("Unknown protocol version.")
    try:
        return ChaCha20Poly1305(key).decrypt(raw[1:13], raw[13:], b"phantom-msg-v2").decode()
    except InvalidTag:
        raise ValueError("Decryption failed.")

def b64e(b): return base64.b64encode(b).decode()
def b64d(s): return base64.b64decode(s)
def b64u_enc(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def b64u_dec(s):
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)
def ts_fmt(ts): return time.strftime("%H:%M", time.localtime(ts))

def _fmt_bytes(n):
    units = ["B", "KB", "MB", "GB"]
    v = float(max(0, n))
    for u in units:
        if v < 1024 or u == units[-1]:
            return f"{v:.1f} {u}" if u != "B" else f"{int(v)} {u}"
        v /= 1024
    return f"{int(n)} B"

def encode_file_message(meta):
    return FILE_MSG_PREFIX + json.dumps(meta, separators=(",", ":"))

def decode_file_message(text):
    if not isinstance(text, str) or not text.startswith(FILE_MSG_PREFIX):
        return None
    try:
        d = json.loads(text[len(FILE_MSG_PREFIX):])
    except Exception:
        return None
    if not isinstance(d, dict):
        return None
    if d.get("type") != "file":
        return None
    return d

def encode_message_envelope(sender_uid, body):
    return MSG_ENV_PREFIX + json.dumps({"from": sender_uid, "body": body}, separators=(",", ":"))

def decode_message_envelope(text):
    if not isinstance(text, str) or not text.startswith(MSG_ENV_PREFIX):
        return None
    try:
        d = json.loads(text[len(MSG_ENV_PREFIX):])
    except Exception:
        return None
    if not isinstance(d, dict):
        return None
    sender = d.get("from")
    body = d.get("body")
    if not isinstance(sender, str) or not sender:
        return None
    if not isinstance(body, str):
        return None
    return sender, body

def encrypt_file_bytes(raw):
    key = os.urandom(KEYSIZE)
    nonce = os.urandom(NONCE)
    ct = ChaCha20Poly1305(key).encrypt(nonce, raw, FILE_AAD)
    return key, nonce, ct

def decrypt_file_bytes(ciphertext, key, nonce):
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, FILE_AAD)
    except InvalidTag:
        raise ValueError("File decryption failed.")


# --- network -----------------------------------------------------------------

TOR_PROXY = "socks5h://127.0.0.1:9050"
TIMEOUT   = 15
_network_privacy_gate = {"checked": False, "allow_without_tor": False}

def _tor_running():
    try:
        s = socket.create_connection(("127.0.0.1", 9050), timeout=1)
        s.close()
        return True
    except:
        return False

def _network_privacy_preflight():
    # If Tor becomes active later, allow immediately without prompting again.
    if _tor_running():
        _network_privacy_gate["checked"] = True
        _network_privacy_gate["allow_without_tor"] = True
        return True
    if _network_privacy_gate["checked"]:
        return _network_privacy_gate["allow_without_tor"]
    console.print()
    console.print(Panel(
        "[bold yellow]Tor is not running.[/bold yellow]\n\n"
        "Your IP can be exposed to network endpoints.\n"
        "To hide your IP, enable Tor or use a trusted VPN.",
        title="Privacy Failsafe",
        border_style="yellow"
    ))
    allow = Confirm.ask("Continue with network actions without Tor?", default=False)
    _network_privacy_gate["checked"] = True
    _network_privacy_gate["allow_without_tor"] = bool(allow)
    return _network_privacy_gate["allow_without_tor"]

def _require_network_privacy_ok():
    if not _network_privacy_preflight():
        raise RuntimeError("Network action cancelled: Tor is off and continuing was not approved.")

def _make_session(tor):
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5)
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    if tor:
        s.proxies = {"http": TOR_PROXY, "https": TOR_PROXY}
    s.headers.clear()
    s.headers["Content-Type"] = "application/json"
    return s

class Relay:
    def __init__(self, auth_priv=None, auth_uid=None, sign_priv=None):
        self.tor = _tor_running()
        self.s   = _make_session(self.tor)
        self.auth_priv = auth_priv
        self.auth_uid = auth_uid
        self.sign_priv = sign_priv
        self.auth_required = False
        self.auth_pub_b64 = None

    def _post(self, path, data, headers=None):
        wire = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
        merged_headers = {}
        if headers:
            merged_headers.update(headers)
        merged_headers.update(self._signed_headers("POST", path, wire))
        _require_network_privacy_ok()
        r = self.s.post(f"{RELAY_URL}{path}", data=wire, timeout=TIMEOUT, headers=merged_headers)
        r.raise_for_status()
        return r.json()

    def _get(self, path):
        headers = self._signed_headers("GET", path, b"")
        _require_network_privacy_ok()
        r = self.s.get(f"{RELAY_URL}{path}", timeout=TIMEOUT, headers=headers)
        r.raise_for_status()
        return r.json()

    def _signed_headers(self, method, path, body):
        # Public endpoints stay unsigned.
        if method == "GET" and (path == "/health" or path.startswith("/pubkey/")):
            return {}
        if method == "POST" and path == "/register":
            return {}
        if not self.auth_uid or not self.sign_priv:
            raise RuntimeError("Authenticated endpoint requires local signing key.")
        ts = str(int(time.time()))
        nonce = b64u_enc(os.urandom(12))
        body_hash = hashlib.sha256(body).hexdigest()
        msg = "\n".join([method.upper(), path, self.auth_uid, ts, nonce, body_hash]).encode()
        sig = Ed25519PrivateKey.from_private_bytes(self.sign_priv).sign(msg)
        return {
            "x-phantom-uid": self.auth_uid,
            "x-phantom-ts": ts,
            "x-phantom-nonce": nonce,
            "x-phantom-sig": b64u_enc(sig),
        }

    def ok(self):
        try:
            health = self._get("/health")
            self.auth_required = bool(health.get("auth_required", False))
            self.auth_pub_b64 = health.get("auth_pub")
            return health.get("status") == "ok"
        except:
            return False

    def register(self, uid, pub_b64, sign_pub_b64):
        self._post("/register", {"uid": uid, "pub_key": pub_b64, "sign_pub": sign_pub_b64})

    def pubkey(self, uid):
        try:
            return self._get(f"/pubkey/{uid}").get("pub_key")
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise

    def send(self, room_id, sender_id, ct):
        return self._post("/send", {"room_id": room_id, "sender_id": sender_id, "ciphertext": ct}).get("ts", 0)

    def upload_file_bytes(self, room_id, sender_id, filename, payload, mime="application/octet-stream", progress_cb=None):
        _require_network_privacy_ok()
        url = f"{RELAY_URL}/file/upload"
        encoder = MultipartEncoder(fields={
            "room_id": room_id,
            "sender_id": sender_id,
            # Avoid leaking local filename/type via multipart metadata.
            "file": ("blob.bin", payload, "application/octet-stream"),
        })

        def _on_progress(m):
            if progress_cb:
                progress_cb(m.bytes_read, encoder.len)

        body = encoder.to_string()
        if progress_cb:
            progress_cb(len(body), len(body))
        headers = {"Content-Type": encoder.content_type}
        headers.update(self._signed_headers("POST", "/file/upload", body))
        kwargs = {"timeout": TIMEOUT}
        if self.tor:
            kwargs["proxies"] = {"http": TOR_PROXY, "https": TOR_PROXY}
        r = requests.post(url, data=body, headers=headers, **kwargs)
        r.raise_for_status()
        out = r.json()
        rel = str(out.get("url", ""))
        if rel.startswith("/"):
            out["url"] = RELAY_URL.rstrip("/") + rel
        return out

    def download_file_bytes(self, url):
        _require_network_privacy_ok()
        kwargs = {"timeout": TIMEOUT}
        if self.tor:
            kwargs["proxies"] = {"http": TOR_PROXY, "https": TOR_PROXY}
        path = "/" + urlparse(url).path.lstrip("/")
        headers = self._signed_headers("GET", path, b"")
        r = requests.get(url, headers=headers, **kwargs)
        r.raise_for_status()
        return r.content

    def fetch(self, room_id, since=None, limit=50):
        b = {"room_id": room_id, "limit": limit}
        if since:
            b["since_ts"] = since
        return self._post("/fetch", b).get("messages", [])

    def burn(self, room_id, sender_id):
        self._post("/burn", {"room_id": room_id, "sender_id": sender_id}, headers=self._burn_headers(sender_id, room_id))

    def _burn_headers(self, sender_id, room_id):
        if self.auth_pub_b64 is None:
            self.ok()
        if self.auth_required and not self.auth_pub_b64:
            raise RuntimeError("Relay requires burn auth but did not provide an auth public key.")
        if not self.auth_pub_b64:
            return None
        if not self.auth_priv:
            raise RuntimeError("Cannot authenticate burn: local identity key unavailable.")
        ts = int(time.time())
        nonce = b64e(os.urandom(12))
        server_pub = X25519PublicKey.from_public_bytes(b64d(self.auth_pub_b64))
        shared = X25519PrivateKey.from_private_bytes(self.auth_priv).exchange(server_pub)
        key = hashlib.sha256(b"phantom-relay-auth-v1" + shared + sender_id.encode()).digest()
        payload = f"burn:{sender_id}:{room_id}:{ts}:{nonce}".encode()
        sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return {
            "x-phantom-ts": str(ts),
            "x-phantom-nonce": nonce,
            "x-phantom-signature": sig,
        }

    def ke_push(self, frm, to, pub, room_id):
        self._post("/ke/push", {"from_uid": frm, "to_uid": to, "pub_key": pub, "room_id": room_id})

    def ke_pop(self, uid):
        return self._get(f"/ke/pop/{uid}").get("entries", [])

    def live(self, room_id, on_msg, stop):
        if self.tor:
            self._poll(room_id, on_msg, stop)
            return
        ws_path = f"/ws/{room_id}"
        ws_url = RELAY_URL.replace("https://", "wss://").replace("http://", "ws://") + ws_path
        ws_headers = [f"{k}: {v}" for k, v in self._signed_headers("GET", ws_path, b"").items()]
        ws_ref = {"app": None}

        def _close_when_stopped():
            stop.wait()
            app = ws_ref.get("app")
            if app is not None:
                try:
                    app.close()
                except:
                    pass

        threading.Thread(target=_close_when_stopped, daemon=True).start()

        def _run():
            while not stop.is_set():
                try:
                    app = _ws.WebSocketApp(
                        ws_url,
                        header=ws_headers,
                        on_message=lambda ws, m: on_msg(json.loads(m)),
                        on_error=lambda ws, e: None
                    )
                    ws_ref["app"] = app
                    app.run_forever(ping_interval=25, ping_payload="ping")
                except:
                    pass
                finally:
                    ws_ref["app"] = None
                if not stop.is_set():
                    time.sleep(3)
        threading.Thread(target=_run, daemon=True).start()

    def _poll(self, room_id, on_msg, stop):
        last = (int(time.time()) // 60 - 1) * 60
        seen = set()
        def _run():
            nonlocal last
            while not stop.is_set():
                try:
                    for m in self.fetch(room_id, since=last - 120, limit=30):
                        k = (m["ts"], m["ciphertext"][:16])
                        if k not in seen:
                            seen.add(k)
                            on_msg(m)
                            if m["ts"] > last:
                                last = m["ts"]
                except:
                    pass
                stop.wait(3)
        threading.Thread(target=_run, daemon=True).start()

#random motd
def get_motd():
    global _motd_cache, _motd_current
    st = load_settings()
    profile = _motd_profile_pick(st.get("motd_profile", DEFAULT_MOTD_PROFILE))
    locked_profile = _motd_profile_pick(st.get("motd_locked_profile", ""), allow_empty=True)
    locked_line = str(st.get("motd_locked_line", "")).strip()
    if locked_profile == profile and locked_line:
        _motd_current = {"profile": profile, "line": locked_line}
        return locked_line
    if _motd_current.get("profile") == profile and _motd_current.get("line"):
        return _motd_current["line"]
    if profile == CUSTOM_MOTD_PROFILE:
        motds = _motd_custom_norm(st.get("motd_custom_lines", []))
        if not motds:
            return "No custom MOTD set. Add one in Settings."
        line = random.choice(motds)
        _motd_current = {"profile": profile, "line": line}
        if st.get("motd_locked_profile", "") != profile or st.get("motd_locked_line", "") != line:
            st["motd_locked_profile"] = profile
            st["motd_locked_line"] = line
            save_settings(st)
        return line
    now = int(time.time())
    # Cache for 5 minutes to avoid fetching on every menu redraw.
    if (
        _motd_cache.get("profile") == profile
        and now - int(_motd_cache.get("fetched_at", 0)) < 300
        and _motd_cache.get("lines")
    ):
        line = random.choice(_motd_cache["lines"])
        _motd_current = {"profile": profile, "line": line}
        st["motd_locked_profile"] = profile
        st["motd_locked_line"] = line
        save_settings(st)
        return line
    try:
        _require_network_privacy_ok()
        response = requests.get(MOTD_URLS[profile], timeout=5)
        response.raise_for_status()
        motds = [
            line.strip()
            for line in response.text.splitlines()
            if line.strip()
        ]
        if not motds:
            return None
        _motd_cache = {"profile": profile, "lines": motds, "fetched_at": now}
        line = random.choice(motds)
        _motd_current = {"profile": profile, "line": line}
        st["motd_locked_profile"] = profile
        st["motd_locked_line"] = line
        save_settings(st)
        return line
    except Exception:
        # Keep working even if endpoint is down; reuse stale cache if present.
        if _motd_current.get("profile") == profile and _motd_current.get("line"):
            return _motd_current["line"]
        if _motd_cache.get("profile") == profile and _motd_cache.get("lines"):
            line = random.choice(_motd_cache["lines"])
            _motd_current = {"profile": profile, "line": line}
            st["motd_locked_profile"] = profile
            st["motd_locked_line"] = line
            save_settings(st)
            return line
        return None

# --- local state -------------------------------------------------------------

def load_contacts():
    migrated = False
    if CON_FILE.exists():
        with open(CON_FILE) as f:
            raw = json.load(f)
        contacts = {}
        if isinstance(raw, dict):
            for uid, entry in raw.items():
                if isinstance(entry, str):
                    fp = contact_fingerprint(entry)
                    contacts[uid] = {"pub_key": entry, "nickname": "", "verified_fp": "", "last_seen_fp": fp}
                    migrated = True
                elif isinstance(entry, dict):
                    pub_key = entry.get("pub_key") or entry.get("pub_key_b64") or ""
                    nickname = str(entry.get("nickname", "")).strip()
                    verified_fp = str(entry.get("verified_fp", "")).strip().upper()
                    last_seen_fp = str(entry.get("last_seen_fp", "")).strip().upper()
                    if pub_key and not last_seen_fp:
                        last_seen_fp = contact_fingerprint(pub_key)
                        migrated = True
                    contacts[uid] = {
                        "pub_key": pub_key,
                        "nickname": nickname,
                        "verified_fp": verified_fp,
                        "last_seen_fp": last_seen_fp,
                    }
                else:
                    migrated = True
            if migrated:
                save_contacts(contacts)
            return contacts
    return {}

def save_contacts(c):
    normalized = {}
    for uid, entry in c.items():
        if isinstance(entry, str):
            normalized[uid] = {
                "pub_key": entry,
                "nickname": "",
                "verified_fp": "",
                "last_seen_fp": contact_fingerprint(entry),
            }
            continue
        normalized[uid] = {
            "pub_key": str(entry.get("pub_key", "")),
            "nickname": str(entry.get("nickname", "")).strip(),
            "verified_fp": str(entry.get("verified_fp", "")).strip().upper(),
            "last_seen_fp": str(entry.get("last_seen_fp", "")).strip().upper(),
        }
    with open(CON_FILE, "w") as f:
        json.dump(normalized, f, indent=2)
    _safe_chmod(CON_FILE, 0o600)

def contact_pub(contacts, uid):
    return contacts.get(uid, {}).get("pub_key", "")

def contact_nick(contacts, uid):
    return contacts.get(uid, {}).get("nickname", "").strip()

def contact_display(contacts, uid):
    nick = contact_nick(contacts, uid)
    return f"{nick} ({uid})" if nick else uid

def short_contact_display(contacts, uid, max_len=16):
    label = contact_nick(contacts, uid) or uid
    return label if len(label) <= max_len else label[:max_len - 3] + "..."

def upsert_contact(contacts, uid, pub_key=None, nickname=None):
    entry = contacts.get(uid, {"pub_key": "", "nickname": "", "verified_fp": "", "last_seen_fp": ""})
    if pub_key is not None:
        entry["pub_key"] = pub_key
        entry["last_seen_fp"] = contact_fingerprint(pub_key)
    if nickname is not None:
        entry["nickname"] = nickname.strip()
    contacts[uid] = entry

def contact_fingerprint(pub_key_b64):
    if not pub_key_b64:
        return ""
    raw = hashlib.sha256(b64d(pub_key_b64)).digest()
    fp = base64.b32encode(raw).decode().rstrip("=").upper()
    return " ".join(fp[i:i+4] for i in range(0, len(fp), 4))

def contact_verified_fp(contacts, uid):
    return contacts.get(uid, {}).get("verified_fp", "").strip().upper()

def trust_contact_key(contacts, uid):
    pub = contact_pub(contacts, uid)
    if not pub:
        return False
    fp = contact_fingerprint(pub)
    entry = contacts.get(uid, {"pub_key": "", "nickname": "", "verified_fp": "", "last_seen_fp": ""})
    entry["verified_fp"] = fp
    entry["last_seen_fp"] = fp
    contacts[uid] = entry
    return True

def ensure_contact_key_safe(contacts, uid, pub_key_b64):
    new_fp = contact_fingerprint(pub_key_b64)
    old_pub = contact_pub(contacts, uid)
    old_fp = contact_fingerprint(old_pub) if old_pub else ""
    pinned_fp = contact_verified_fp(contacts, uid)
    if pinned_fp and pinned_fp != new_fp:
        raise RuntimeError(
            f"Contact key changed for {uid}.\n"
            f"Trusted: {pinned_fp}\n"
            f"Current: {new_fp}\n"
            "Blocked. Verify out-of-band, then run: python phantom.py verify <uid> --force"
        )
    if old_pub and old_pub != pub_key_b64 and not pinned_fp:
        console.print("[yellow]Warning: contact key changed and is not pinned.[/yellow]")
        if old_fp:
            console.print(f"[yellow]Old:[/yellow] {old_fp}")
        console.print(f"[yellow]New:[/yellow] {new_fp}")
    upsert_contact(contacts, uid, pub_key=pub_key_b64)
    return new_fp

def resolve_contact_pick(contacts, pick, contact_list):
    if pick.isdigit() and 1 <= int(pick) <= len(contact_list):
        return contact_list[int(pick) - 1]
    if pick in contacts:
        return pick
    low = pick.lower()
    for uid in contact_list:
        if contact_nick(contacts, uid).lower() == low and low:
            return uid
    return None

def _safe_chmod(path, mode):
    try:
        os.chmod(path, mode)
    except OSError:
        pass

def load_settings():
    defaults = {
        "show_no_tor_warning": True,
        "update_checks": True,
        "ascii_animal": "none",
        "theme": DEFAULT_THEME,
        "theme_custom": dict(CUSTOM_THEME_DEFAULT),
        "motd_profile": DEFAULT_MOTD_PROFILE,
        "motd_custom_lines": [],
        "motd_locked_profile": "",
        "motd_locked_line": "",
        "last_update_check_ts": 0,
        "last_update_version_seen": "",
        "update_spki_sha256": "",
    }
    if not SET_FILE.exists():
        return defaults
    try:
        with open(SET_FILE) as f:
            data = json.load(f)
        out = dict(defaults)
        if isinstance(data, dict):
            out["show_no_tor_warning"] = bool(data.get("show_no_tor_warning", True))
            out["update_checks"] = bool(data.get("update_checks", True))
            raw_animal = str(data.get("ascii_animal", "")).strip().lower()
            if raw_animal in ("none", "cat", "dog", "penguin", "bear", "ghost"):
                out["ascii_animal"] = raw_animal
            elif bool(data.get("cat_mode", False)):
                # Backward compatibility with old cat toggle.
                out["ascii_animal"] = "cat"
            theme_raw = str(data.get("theme", DEFAULT_THEME)).strip().lower()
            out["theme"] = theme_raw if theme_raw in _theme_names() else DEFAULT_THEME
            out["theme_custom"] = _theme_custom_norm(data.get("theme_custom", {}))
            out["motd_profile"] = _motd_profile_pick(str(data.get("motd_profile", DEFAULT_MOTD_PROFILE)))
            out["motd_custom_lines"] = _motd_custom_norm(data.get("motd_custom_lines", []))
            locked_profile = _motd_profile_pick(str(data.get("motd_locked_profile", "")), allow_empty=True)
            locked_line = str(data.get("motd_locked_line", "")).strip()
            out["motd_locked_profile"] = locked_profile
            out["motd_locked_line"] = locked_line if locked_profile else ""
            out["last_update_check_ts"] = int(data.get("last_update_check_ts", 0) or 0)
            out["last_update_version_seen"] = str(data.get("last_update_version_seen", ""))
            out["update_spki_sha256"] = str(data.get("update_spki_sha256", ""))
        return out
    except:
        return defaults

def save_settings(settings):
    animal = str(settings.get("ascii_animal", "none")).strip().lower()
    if animal not in ("none", "cat", "dog", "penguin", "bear", "ghost"):
        animal = "none"
    merged = {
        "show_no_tor_warning": bool(settings.get("show_no_tor_warning", True)),
        "update_checks": bool(settings.get("update_checks", True)),
        "ascii_animal": animal,
        "theme": (str(settings.get("theme", DEFAULT_THEME)).strip().lower() if str(settings.get("theme", DEFAULT_THEME)).strip().lower() in _theme_names() else DEFAULT_THEME),
        "theme_custom": _theme_custom_norm(settings.get("theme_custom", {})),
        "motd_profile": _motd_profile_pick(str(settings.get("motd_profile", DEFAULT_MOTD_PROFILE))),
        "motd_custom_lines": _motd_custom_norm(settings.get("motd_custom_lines", [])),
        "motd_locked_profile": _motd_profile_pick(str(settings.get("motd_locked_profile", "")), allow_empty=True),
        "motd_locked_line": str(settings.get("motd_locked_line", "")).strip(),
        "last_update_check_ts": int(settings.get("last_update_check_ts", 0) or 0),
        "last_update_version_seen": str(settings.get("last_update_version_seen", "")),
        "update_spki_sha256": str(settings.get("update_spki_sha256", "")),
    }
    if not merged["motd_locked_profile"]:
        merged["motd_locked_line"] = ""
    with open(SET_FILE, "w") as f:
        json.dump(merged, f, indent=2)
    _safe_chmod(SET_FILE, 0o600)

def startup_file_path():
    system = platform.system()
    if system == "Windows":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            return None
        return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "phantom-startup.bat"
    if system == "Darwin":
        return Path.home() / "Library" / "LaunchAgents" / "com.phantom.chat.plist"
    return Path.home() / ".config" / "autostart" / "phantom.desktop"

def startup_status():
    p = startup_file_path()
    return bool(p and p.exists())

def startup_enable():
    p = startup_file_path()
    if not p:
        raise RuntimeError("Startup path not available on this system.")
    p.parent.mkdir(parents=True, exist_ok=True)
    py = Path(sys.executable).resolve()
    app = Path(__file__).resolve()
    system = platform.system()
    if system == "Windows":
        content = (
            "@echo off\n"
            f"\"{py}\" \"{app}\" >NUL 2>&1\n"
        )
    elif system == "Darwin":
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key><string>com.phantom.chat</string>
    <key>ProgramArguments</key>
    <array>
      <string>{py}</string>
      <string>{app}</string>
    </array>
    <key>RunAtLoad</key><true/>
  </dict>
</plist>
"""
    else:
        content = (
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=Phantom\n"
            f"Exec=\"{py}\" \"{app}\"\n"
            "X-GNOME-Autostart-enabled=true\n"
            "NoDisplay=false\n"
        )
    with open(p, "w") as f:
        f.write(content)
    return p

def startup_disable():
    p = startup_file_path()
    if p and p.exists():
        p.unlink()
        return True
    return False

def cmd_startup(action=None):
    act = (action or "status").lower()
    try:
        if act == "status":
            console.print(f"[dim]Startup: {'enabled' if startup_status() else 'disabled'}[/dim]")
            return
        if act == "enable":
            p = startup_enable()
            console.print(f"[green]Startup enabled.[/green] [dim]{p}[/dim]")
            return
        if act == "disable":
            if startup_disable():
                console.print("[green]Startup disabled.[/green]")
            else:
                console.print("[dim]Startup already disabled.[/dim]")
            return
        console.print("[red]Usage: phantom.py startup <enable|disable|status>[/red]")
    except Exception as e:
        console.print(f"[red]Startup action failed: {e}[/red]")

def cmd_warning(action=None):
    st = load_settings()
    act = (action or "status").lower()
    if act == "status":
        console.print(f"[dim]No-Tor warning: {'on' if st['show_no_tor_warning'] else 'off'}[/dim]")
        return
    if act in ("on", "enable"):
        st["show_no_tor_warning"] = True
        save_settings(st)
        console.print("[green]No-Tor warning enabled.[/green]")
        return
    if act in ("off", "disable"):
        st["show_no_tor_warning"] = False
        save_settings(st)
        console.print("[green]No-Tor warning disabled.[/green]")
        return
    console.print("[red]Usage: phantom.py warning <on|off|status>[/red]")

def cmd_updates(action=None):
    st = load_settings()
    act = (action or "status").lower()
    if act == "status":
        pin = st.get("update_spki_sha256", "")
        pin_status = "set" if pin else "not set"
        console.print(f"[dim]Update checks: {'on' if st.get('update_checks', True) else 'off'} | update key pin: {pin_status}[/dim]")
        return
    if act in ("on", "enable"):
        st["update_checks"] = True
        save_settings(st)
        console.print("[green]Update checks enabled.[/green]")
        return
    if act in ("off", "disable"):
        st["update_checks"] = False
        save_settings(st)
        console.print("[green]Update checks disabled.[/green]")
        return
    if act in ("reset-pin", "resetpin", "pin-reset"):
        st["update_spki_sha256"] = ""
        save_settings(st)
        console.print("[yellow]Updater key pin reset.[/yellow] Next update check will ask to trust again.")
        return
    console.print("[red]Usage: phantom.py updates <on|off|status|reset-pin>[/red]")

def cmd_theme(action=None):
    st = load_settings()
    act = (action or "status").strip().lower()
    if act in ("status", ""):
        console.print(f"[dim]Theme: {st.get('theme', DEFAULT_THEME)}[/dim]")
        return
    if act in ("list", "ls"):
        console.print(f"[dim]Available themes:[/dim] {', '.join(_theme_names())}")
        return
    if act.startswith("set "):
        act = act[4:].strip().lower()
    if act not in _theme_names():
        console.print(f"[red]Unknown theme: {act}[/red]")
        console.print(f"[dim]Available:[/dim] {', '.join(_theme_names())}")
        return
    st["theme"] = act
    save_settings(st)
    _set_ui_context(_ui_relay_ctx[0])
    console.print(f"[green]Theme set:[/green] {act}")

def _tor_setup_hint():
    system = platform.system()
    if system == "Linux":
        return (
            "To hide your IP, install/start Tor (examples):\n"
            "Debian/Ubuntu: sudo apt install tor && sudo systemctl enable --now tor\n"
            "Fedora: sudo dnf install tor && sudo systemctl enable --now tor\n"
            "Arch: sudo pacman -S tor && sudo systemctl enable --now tor"
        )
    if system == "Darwin":
        return "To hide your IP, install Tor Browser or run Tor (Homebrew: brew install tor)."
    if system == "Windows":
        return "To hide your IP, install and run Tor Browser (or Expert Bundle Tor service)."
    return "To hide your IP, run a local Tor SOCKS proxy on 127.0.0.1:9050."

def _version_tuple(v):
    parts = [int(x) for x in re.findall(r"\d+", str(v))]
    return tuple(parts or [0])

def _extract_remote_version(script_text):
    m = re.search(r'^\s*APP_VERSION\s*=\s*["\']([^"\']+)["\']', script_text, flags=re.MULTILINE)
    if m:
        return m.group(1).strip()
    return None

def _extract_remote_changes(script_text):
    m = re.search(
        r'^\s*APP_CHANGES\s*=\s*(?P<q>"""|\'\'\')(?P<body>.*?)(?P=q)',
        script_text,
        flags=re.MULTILINE | re.DOTALL
    )
    if not m:
        return ""
    body = m.group("body")
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    # Keep prompt compact and predictable.
    return "\n".join(lines[:8]).strip()

def _download_update_instructions():
    if platform.system() == "Windows":
        return (
            "Invoke-WebRequest https://noks.pics/phantom.py -OutFile phantom.py\n"
            "py -3 phantom.py"
        )
    return (
        "curl -fsSL https://noks.pics/phantom.py -o phantom.py\n"
        "python3 phantom.py"
    )

def _update_endpoint_spki_sha256():
    _require_network_privacy_ok()
    u = urlparse(UPDATE_URL)
    if u.scheme.lower() != "https" or not u.hostname:
        raise RuntimeError("UPDATE_URL must be an https URL.")
    port = u.port or 443
    ctx = ssl.create_default_context()
    with socket.create_connection((u.hostname, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=u.hostname) as tls:
            cert_der = tls.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(cert_der)
    spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()

def _verify_or_pin_update_key(force=False):
    current = _update_endpoint_spki_sha256()
    st = load_settings()
    pinned = st.get("update_spki_sha256", "")

    if not pinned:
        console.print()
        console.print(Panel(
            "Updater trust (first use)\n\n"
            f"Host: {urlparse(UPDATE_URL).hostname}\n"
            f"SPKI SHA256: {current}\n\n"
            "Store this key pin and trust updates from this endpoint?",
            border_style="yellow"
        ))
        if not Confirm.ask("Trust and save updater key pin?", default=True):
            return False
        st["update_spki_sha256"] = current
        save_settings(st)
        return True

    if pinned != current:
        console.print()
        console.print(Panel(
            "Updater key pin mismatch.\n\n"
            f"Pinned:  {pinned}\n"
            f"Current: {current}\n\n"
            "Auto-update is blocked. This may be endpoint compromise or certificate key rotation.",
            border_style="red"
        ))
        if force and Confirm.ask("Accept new updater key and replace pin?", default=False):
            st["update_spki_sha256"] = current
            save_settings(st)
            return True
        return False

    return True

def _apply_self_update(expected_remote_version=None):
    if not _verify_or_pin_update_key(force=True):
        raise RuntimeError("Updater key not trusted.")
    _require_network_privacy_ok()
    r = requests.get(UPDATE_URL, timeout=10)
    r.raise_for_status()
    script_text = r.text
    remote_ver = _extract_remote_version(script_text)
    if not remote_ver:
        raise RuntimeError("Remote script does not expose APP_VERSION.")
    if expected_remote_version and remote_ver != expected_remote_version:
        raise RuntimeError(f"Version changed during update check ({expected_remote_version} -> {remote_ver}). Try again.")

    target = Path(__file__).resolve()
    tmp = target.with_name(target.name + ".new")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(script_text)

    os.replace(tmp, target)
    return remote_ver

def check_for_updates(force=False):
    settings = load_settings()
    if not settings.get("update_checks", True) and not force:
        return None
    now = int(time.time())
    if (
        not force
        and UPDATE_CHECK_COOLDOWN_SECONDS > 0
        and now - settings.get("last_update_check_ts", 0) < UPDATE_CHECK_COOLDOWN_SECONDS
    ):
        return None

    settings["last_update_check_ts"] = now
    save_settings(settings)

    if not _verify_or_pin_update_key(force=force):
        return None

    try:
        _require_network_privacy_ok()
        r = requests.get(UPDATE_URL, timeout=5)
        r.raise_for_status()
    except:
        return None

    probe = r.text[:24000]
    remote_ver = _extract_remote_version(probe)
    if not remote_ver:
        return None
    if _version_tuple(remote_ver) <= _version_tuple(APP_VERSION):
        return None

    settings["last_update_version_seen"] = remote_ver
    save_settings(settings)
    return {"current": APP_VERSION, "remote": remote_ver, "changes": _extract_remote_changes(probe)}

def maybe_prompt_update(force=False):
    info = check_for_updates(force=force)
    if not info:
        if force:
            console.print(f"[dim]No update found. You are on {APP_VERSION}.[/dim]")
        return

    console.print()
    changes = (info.get("changes") or "").strip()
    changes_block = f"[bold]Changes[/bold]\n{changes}\n\n" if changes else ""
    console.print(Panel(
        f"[bold yellow]Update available[/bold yellow]\n\n"
        f"Current: [cyan]{info['current']}[/cyan]\n"
        f"Latest:  [green]{info['remote']}[/green]\n\n"
        f"{changes_block}"
        "Download and restart now?",
        border_style="yellow"
    ))
    if Confirm.ask("Apply update now?", default=True):
        try:
            new_ver = _apply_self_update(expected_remote_version=info["remote"])
            console.print(f"[green]Updated to {new_ver}.[/green]")
            changes = (info.get("changes") or "").strip()
            if changes:
                console.print()
                console.print(Panel(
                    f"[bold]What changed in {new_ver}[/bold]\n\n{changes}",
                    border_style="green"
                ))
            if Confirm.ask("Restart Phantom now?", default=True):
                os.execv(sys.executable, [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])
        except Exception as e:
            console.print(f"[red]Auto-update failed:[/red] {e}")
            console.print()
            console.print("[bold]Run manually:[/bold]")
            console.print(f"[green]{_download_update_instructions()}[/green]")

def unlock():
    if not ID_FILE.exists():
        console.print("[red]No identity found.[/red] Run the app without arguments to set up.")
        sys.exit(1)
    pw = getpass.getpass("Password: ")

    try:
        enc_priv, enc_pub, sign_priv, sign_pub = load_identity(str(ID_FILE), pw)
        if not sign_priv or not sign_pub:
            raise ValueError("Identity missing signing key. Re-register with the latest version.")
        return enc_priv, enc_pub, sign_priv, sign_pub, uid_of(enc_pub)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)


# --- first run wizard --------------------------------------------------------

def first_run_wizard():
    clear()
    console.print()
    console.print(Panel(
        "Welcome to Phantom.\n\n"
        "Your messages are encrypted end-to-end before they leave this device.\n"
        "The relay stores encrypted content, but may still see network metadata (including IP when not effectively routed through Tor).\n\n"
        "This wizard will create your identity. It takes about 30 seconds.",
        title="Phantom — Private Messaging",
        border_style="cyan"
    ))
    console.print()
    input("Press Enter to continue...")
    console.print()

    console.print("[bold]Step 1 of 3 — Checking server connection[/bold]")
    console.print(f"Connecting to relay...")

    relay = Relay()
    if relay.tor:
        console.print("[green]Tor detected. Your IP is hidden.[/green]")
    else:
        console.print("[dim]Tor not detected. Traffic goes directly to relay.[/dim]")
        console.print(f"[dim]{_tor_setup_hint()}[/dim]")

    if not relay.ok():
        console.print()
        console.print("[yellow]Warning: relay is not responding right now.[/yellow]")
        console.print("The server may be waking up (this can take 30 seconds).")
        console.print("You can still create your identity and register later.")
        console.print()

    console.print()
    console.print("[bold]Step 2 of 3 — Create your identity[/bold]")
    console.print("Your identity is an encryption keypair stored locally on this device.")
    console.print("It is protected by a password you choose now.\n")
    console.print("[dim]Use a strong password. If you forget it, your identity cannot be recovered.[/dim]")
    console.print()

    while True:
        pw = getpass.getpass("Choose a password: ")
        if len(pw) < 6:
            console.print("[red]Password too short. Use at least 6 characters.[/red]")
            continue
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            console.print("[red]Passwords do not match. Try again.[/red]")
            continue
        break

    console.print()
    console.print("Creating identity (this takes a few seconds)...")

    enc_priv, enc_pub, sign_priv, sign_pub = gen_keypair()
    save_identity(str(ID_FILE), enc_priv, enc_pub, sign_priv, sign_pub, pw)
    _safe_chmod(ID_FILE, 0o600)
    uid = uid_of(enc_pub)

    if relay.ok():
        try:
            relay.register(uid, b64e(enc_pub), b64u_enc(sign_pub))
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 409:
                console.print("[yellow]UID already registered on relay.[/yellow]")
            else:
                raise

    INIT_FLAG.touch()

    console.print()
    console.print("[bold]Step 3 of 3 — Choose defaults[/bold]")
    settings = load_settings()

    update_on = Confirm.ask(
        "Enable automatic update checks at startup?",
        default=settings.get("update_checks", True)
    )
    settings["update_checks"] = bool(update_on)
    save_settings(settings)

    startup_on = Confirm.ask(
        "Run Phantom automatically at system startup?",
        default=False
    )
    try:
        if startup_on:
            startup_enable()
            console.print("[green]Startup enabled.[/green]")
        else:
            startup_disable()
            console.print("[dim]Startup left disabled.[/dim]")
    except Exception as e:
        console.print(f"[yellow]Could not change startup setting: {e}[/yellow]")

    console.print()
    console.print(Panel(
        f"Identity created.\n\n"
        f"[bold]Your uid[/bold]\n\n"
        f"[cyan]{uid}[/cyan]\n\n"
        "This is your address. Share it with anyone who wants to message you.\n\n"
        "[dim]Your identity file: ~/.phantom/identity.json\n"
        "Back it up. If it is lost, it cannot be recovered.[/dim]",
        title="Ready",
        border_style="green"
    ))
    console.print()
    console.print("[bold]What to do next:[/bold]")
    console.print("  Share your uid with a contact")
    console.print("  When they share theirs, run:  [bold]python phantom.py add <their uid>[/bold]")
    console.print("  Then start chatting:           [bold]python phantom.py chat <their uid>[/bold]")
    console.print()


# --- commands ----------------------------------------------------------------

def cmd_register():
    if ID_FILE.exists():
        if not Confirm.ask("An identity already exists. Overwrite it?", default=False):
            return
    console.print()
    console.print("Creating a new identity.\n")
    while True:
        pw = getpass.getpass("Choose a password: ")
        if len(pw) < 6:
            console.print("[red]Too short. Use at least 6 characters.[/red]")
            continue
        if pw != getpass.getpass("Confirm password: "):
            console.print("[red]Passwords do not match.[/red]")
            continue
        break

    console.print("\nGenerating keypair...")
    enc_priv, enc_pub, sign_priv, sign_pub = gen_keypair()
    save_identity(str(ID_FILE), enc_priv, enc_pub, sign_priv, sign_pub, pw)
    _safe_chmod(ID_FILE, 0o600)
    uid = uid_of(enc_pub)

    relay = Relay()
    if relay.ok():
        try:
            relay.register(uid, b64e(enc_pub), b64u_enc(sign_pub))
            console.print("[green]Registered with server.[/green]")
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 409:
                console.print("[yellow]UID already exists on relay (register is create-only).[/yellow]")
            else:
                raise
    else:
        console.print("[yellow]Relay unreachable. Run 'register' again when online.[/yellow]")

    INIT_FLAG.touch()
    console.print()
    console.print(Panel(
        f"[bold]Your uid[/bold]\n\n[cyan]{uid}[/cyan]\n\n"
        "[dim]Share this with people who want to message you.\n"
        "Back up ~/.phantom/identity.json — it cannot be recovered.[/dim]",
        title="Identity created",
        border_style="cyan"
    ))


def cmd_whoami():
    enc_priv, enc_pub, sign_priv, _, uid = unlock()
    relay = Relay(auth_priv=enc_priv, auth_uid=uid, sign_priv=sign_priv)
    console.print()
    console.print(Panel(
        f"[bold]uid[/bold]\n\n[cyan]{uid}[/cyan]\n\n"
        f"[dim]Relay:  {RELAY_URL}\n"
        f"Tor:    {'active' if relay.tor else 'not detected'}[/dim]",
        title="Your identity",
        border_style="cyan"
    ))


def cmd_add(peer_uid):
    enc_priv, enc_pub, sign_priv, _, my_uid = unlock()
    relay = Relay(auth_priv=enc_priv, auth_uid=my_uid, sign_priv=sign_priv)

    if not relay.ok():
        console.print("[red]Cannot reach relay.[/red]")
        sys.exit(1)

    console.print(f"Looking up uid...")
    pub_b64 = relay.pubkey(peer_uid)
    if not pub_b64:
        console.print("[red]No user found with that uid.[/red]")
        console.print("Make sure they have registered and gave you the correct uid.")
        sys.exit(1)

    contacts = load_contacts()
    fp = ensure_contact_key_safe(contacts, peer_uid, pub_b64)
    save_contacts(contacts)
    room_id = room_id_of(enc_priv, b64d(pub_b64))
    relay.ke_push(my_uid, peer_uid, b64e(enc_pub), room_id)

    console.print(f"[green]Contact added.[/green]")
    console.print(f"[dim]Fingerprint:[/dim] {fp}")
    if not contact_verified_fp(contacts, peer_uid):
        console.print("[yellow]Not verified yet.[/yellow]")
        if Confirm.ask("Trust this fingerprint now (after out-of-band check)?", default=False):
            trust_contact_key(contacts, peer_uid)
            save_contacts(contacts)
            console.print("[green]Contact fingerprint trusted.[/green]")
        else:
            console.print(f"[dim]You can verify later with:[/dim] [bold]python phantom.py verify {peer_uid}[/bold]")
    console.print(f"Start chatting:  [bold]python phantom.py chat {peer_uid}[/bold]")


def cmd_contacts():
    contacts = load_contacts()
    if not contacts:
        console.print("[dim]No contacts yet.[/dim]")
        console.print("Add one with:  python phantom.py add <uid>")
        return
    t = Table(show_lines=True, border_style="dim")
    t.add_column("Name", style="magenta")
    t.add_column("UID", style="cyan")
    t.add_column("Verified", style="green")
    for uid in contacts:
        t.add_row(contact_nick(contacts, uid) or "-", uid, "yes" if contact_verified_fp(contacts, uid) else "no")
    console.print(t)

def cmd_verify(peer_uid, force=False):
    contacts = load_contacts()
    if peer_uid not in contacts:
        console.print("[red]Contact not found.[/red]")
        return
    pub = contact_pub(contacts, peer_uid)
    if not pub:
        console.print("[red]No contact key available.[/red]")
        return
    fp = contact_fingerprint(pub)
    console.print()
    console.print(Panel(
        f"[bold]Contact[/bold]: {contact_display(contacts, peer_uid)}\n\n"
        f"[bold]Fingerprint[/bold]\n{fp}",
        border_style="cyan",
        title="Verify Contact Key"
    ))
    pinned = contact_verified_fp(contacts, peer_uid)
    if pinned:
        console.print(f"[dim]Currently trusted:[/dim] {pinned}")
    if pinned and pinned == fp and not force:
        console.print("[green]Already verified.[/green]")
        return
    if pinned and pinned != fp and not force:
        console.print("[red]Key differs from trusted fingerprint. Re-run with --force after out-of-band verification.[/red]")
        return
    if Confirm.ask("Mark this fingerprint as trusted?", default=True):
        trust_contact_key(contacts, peer_uid)
        save_contacts(contacts)
        console.print("[green]Contact fingerprint trusted.[/green]")

def cmd_nick(peer_uid, nickname):
    contacts = load_contacts()
    if peer_uid not in contacts:
        console.print("[red]Contact not found.[/red]")
        return
    upsert_contact(contacts, peer_uid, nickname=nickname)
    save_contacts(contacts)
    shown = contact_nick(contacts, peer_uid) or "(none)"
    console.print(f"[green]Nickname updated:[/green] {peer_uid} -> {shown}")

def cmd_remove(peer_uid, my_uid=None, relay=None, my_priv=None):
    if my_uid is None or relay is None or my_priv is None:
        enc_priv, _, sign_priv, _, my_uid = unlock()
        relay = Relay(auth_priv=enc_priv, auth_uid=my_uid, sign_priv=sign_priv)
        my_priv = enc_priv
    contacts = load_contacts()
    if peer_uid not in contacts:
        console.print("[red]Contact not found.[/red]")
        return
    label = contact_display(contacts, peer_uid)
    if not Confirm.ask(f"Remove connection with {label}? This will also delete all messages with them first.", default=False):
        return
    try:
        peer_pub = contact_pub(contacts, peer_uid)
        if not peer_pub:
            raise RuntimeError("Missing peer key for room derivation.")
        relay.burn(room_id_of(my_priv, b64d(peer_pub)), my_uid)
    except Exception as e:
        console.print(f"[red]Could not delete messages first: {e}[/red]")
        console.print("[dim]Contact not removed.[/dim]")
        return
    contacts.pop(peer_uid, None)
    save_contacts(contacts)
    seen = load_seen()
    if peer_uid in seen:
        seen.pop(peer_uid, None)
        save_seen(seen)
    with _notify_lock:
        _notify_unread.pop(peer_uid, None)
    console.print("[green]Messages deleted and connection removed.[/green]")


def cmd_chat(peer_uid, priv=None, pub=None, my_uid=None, relay=None, sign_priv=None):
    if priv is None:
        priv, pub, sign_priv, _, my_uid = unlock()
    if relay is None:
        relay = Relay(auth_priv=priv, auth_uid=my_uid, sign_priv=sign_priv)
    _set_ui_context(relay)

    if not relay.ok():
        console.print("[red]Cannot reach relay.[/red]")
        sys.exit(1)

    contacts = load_contacts()

    for ke in relay.ke_pop(my_uid):
        try:
            ensure_contact_key_safe(contacts, ke["from_uid"], ke["pub_key"])
        except RuntimeError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)
    save_contacts(contacts)

    if peer_uid not in contacts:
        pub_b64 = relay.pubkey(peer_uid)
        if not pub_b64:
            console.print("[red]Peer not found.[/red]")
            sys.exit(1)
        try:
            ensure_contact_key_safe(contacts, peer_uid, pub_b64)
        except RuntimeError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)
        save_contacts(contacts)
        relay.ke_push(my_uid, peer_uid, b64e(pub), room_id_of(priv, b64d(pub_b64)))

    peer_pub = b64d(contact_pub(contacts, peer_uid))
    room     = room_id_of(priv, peer_pub)
    skey     = session_key(priv, peer_pub, my_uid, peer_uid)
    try:
        # Re-push key/room to ensure room_members exists server-side for older contacts.
        relay.ke_push(my_uid, peer_uid, b64e(pub), room)
    except Exception:
        pass

    clear()
    status = "via Tor" if relay.tor else "direct"
    console.print()
    console.print(Panel(
        f"[bold]PhantomChat[/bold]  [dim]{status}[/dim]\n\n"
        f"[dim]Peer:[/dim]  [cyan]{contact_display(contacts, peer_uid)}[/cyan]\n\n"
        f"[dim]Verified key:[/dim]  {'yes' if contact_verified_fp(contacts, peer_uid) else 'no'}\n\n"
        "[dim]Type and press Enter to send\n"
        "/file <path>        upload e2ee file (max 50 MB, expires ~24h)\n"
        "/files              list files in this chat session\n"
        "/get <n> [path]     download + decrypt file #n locally\n"
        "/burn   delete all messages in this conversation\n"
        "/quit   exit[/dim]",
        border_style="green"
    ))
    console.print()

    seen = set()
    seen_lock = threading.Lock()
    file_records = []

    def on_msg(payload, include_self=False):
        if stop.is_set():
            return
        k = (payload.get("ts"), payload.get("ciphertext", "")[:16])
        with seen_lock:
            if k in seen:
                return
            seen.add(k)
        try:
            pt_raw = decrypt(payload["ciphertext"], skey)
            env = decode_message_envelope(pt_raw)
            if env:
                sid, pt = env
            else:
                sid, pt = payload.get("sender_id", ""), pt_raw
            if sid == my_uid and not include_self:
                return
            t  = ts_fmt(payload.get("ts", int(time.time())))
            who = "you" if sid == my_uid else "them"
            color = "green" if sid == my_uid else "cyan"
            fmsg = decode_file_message(pt)
            if fmsg:
                name = str(fmsg.get("name", "file"))
                size = _fmt_bytes(int(fmsg.get("size", 0) or 0))
                url = str(fmsg.get("url", ""))
                rec_idx = None
                if url and fmsg.get("key") and fmsg.get("nonce"):
                    file_records.append({
                        "name": name,
                        "url": url,
                        "key": str(fmsg.get("key", "")),
                        "nonce": str(fmsg.get("nonce", "")),
                        "size": int(fmsg.get("size", 0) or 0),
                    })
                    rec_idx = len(file_records)
                tag = f" [dim]#{rec_idx}[/dim]" if rec_idx else ""
                console.print(f"  [{color}][{t}] {who}[/{color}]  [bold]file[/bold]{tag} {name} ({size})")
                if url:
                    console.print(f"      [blue]{url}[/blue]")
                if rec_idx:
                    console.print(f"      [dim]download: /get {rec_idx}[/dim]")
            else:
                console.print(f"  [{color}][{t}] {who}[/{color}]  {pt}")
        except:
            pass

    _current_chat_peer[0] = peer_uid
    stop = threading.Event()
    relay.live(room, on_msg, stop)

    for m in relay.fetch(room, limit=200):
        on_msg(m, include_self=True)

    try:
        while True:
            try:
                msg = input()
            except EOFError:
                break
            msg = msg.strip()
            if not msg:
                continue
            if msg == "/quit":
                break
            if msg == "/files":
                if not file_records:
                    console.print("  [dim]No downloadable files in this chat session yet.[/dim]")
                    continue
                console.print("  [bold]Files[/bold]")
                for i, rec in enumerate(file_records, 1):
                    console.print(f"  [bold]{i}[/bold]  {rec['name']} ({_fmt_bytes(rec.get('size', 0))})")
                continue
            if msg.startswith("/get "):
                arg = msg[5:].strip()
                if not arg:
                    console.print("  [red]Usage: /get <n> [path][/red]")
                    continue
                parts = arg.split(maxsplit=1)
                try:
                    idx = int(parts[0])
                except ValueError:
                    console.print("  [red]Usage: /get <n> [path][/red]")
                    continue
                if idx < 1 or idx > len(file_records):
                    console.print("  [red]File index not found.[/red]")
                    continue
                rec = file_records[idx - 1]
                if len(parts) > 1 and parts[1].strip():
                    out_path = Path(parts[1].strip()).expanduser()
                    if out_path.exists() and out_path.is_dir():
                        out_path = out_path / rec["name"]
                else:
                    out_path = Path.cwd() / rec["name"]
                if out_path.exists() and not Confirm.ask(f"  Overwrite {out_path}?", default=False):
                    continue
                try:
                    console.print(f"  [dim]Downloading encrypted blob for #{idx}...[/dim]")
                    blob = relay.download_file_bytes(rec["url"])
                    raw = decrypt_file_bytes(blob, b64d(rec["key"]), b64d(rec["nonce"]))
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(out_path, "wb") as f:
                        f.write(raw)
                    console.print(f"  [green]Saved[/green] {out_path} [dim]({_fmt_bytes(len(raw))})[/dim]")
                except Exception as e:
                    console.print(f"  [red]Download/decrypt failed: {e}[/red]")
                continue
            if msg.startswith("/file "):
                raw = msg[6:].strip()
                if not raw:
                    console.print("  [red]Usage: /file <path>[/red]")
                    continue
                fp = Path(raw).expanduser()
                if not fp.exists() or not fp.is_file():
                    console.print("  [red]File not found.[/red]")
                    continue
                try:
                    plain = fp.read_bytes()
                    file_key, file_nonce, ciphertext = encrypt_file_bytes(plain)
                    total_sz = max(1, len(ciphertext))
                    with Progress(
                        TextColumn("  [dim]Uploading[/dim] {task.description}"),
                        BarColumn(bar_width=28),
                        TaskProgressColumn(),
                        TransferSpeedColumn(),
                        TimeRemainingColumn(),
                        transient=True,
                        console=console,
                    ) as prog:
                        task = prog.add_task(fp.name + ".enc", total=total_sz)
                        def _progress(sent, total):
                            prog.update(task, completed=min(sent, total_sz))
                        up = relay.upload_file_bytes(
                            room,
                            my_uid,
                            fp.name + ".enc",
                            ciphertext,
                            mime="application/octet-stream",
                            progress_cb=_progress,
                        )
                    meta = {
                        "type": "file",
                        "name": fp.name,
                        "size": len(plain),
                        "cipher_size": len(ciphertext),
                        "mime": mimetypes.guess_type(fp.name)[0] or "application/octet-stream",
                        "url": str(up.get("url", "")),
                        "key": b64e(file_key),
                        "nonce": b64e(file_nonce),
                    }
                    wire = encode_file_message(meta)
                    ct = encrypt(encode_message_envelope(my_uid, wire), skey)
                    relay.send(room, my_uid, ct)
                    if meta["url"]:
                        file_records.append({
                            "name": meta["name"],
                            "url": meta["url"],
                            "key": meta["key"],
                            "nonce": meta["nonce"],
                            "size": meta["size"],
                        })
                        idx = len(file_records)
                    else:
                        idx = None
                    console.print(f"  [green][{ts_fmt(int(time.time()))}] you[/green]  [bold]file[/bold] {meta['name']} ({_fmt_bytes(meta['size'])})")
                    if meta["url"]:
                        console.print(f"      [blue]{meta['url']}[/blue]")
                    if idx:
                        console.print(f"      [dim]download: /get {idx}[/dim]")
                except Exception as e:
                    console.print(f"  [red]File upload failed: {e}[/red]")
                continue
            if msg == "/burn":
                if Confirm.ask("  Delete all messages in this chat?", default=False) and Confirm.ask("  Final confirmation: permanently delete them now?", default=False):
                    try:
                        relay.burn(room, my_uid)
                        console.print("  [dim]Messages deleted.[/dim]")
                    except Exception as e:
                        console.print(f"  [red]Burn failed: {e}[/red]")
                continue
            ct = encrypt(encode_message_envelope(my_uid, msg), skey)
            relay.send(room, my_uid, ct)
            console.print(f"  [green][{ts_fmt(int(time.time()))}] you[/green]  {msg}")
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        _current_chat_peer[0] = None
        clear()

def cmd_burn(peer_uid):
    priv, _, sign_priv, _, my_uid = unlock()
    relay = Relay(auth_priv=priv, auth_uid=my_uid, sign_priv=sign_priv)
    contacts = load_contacts()
    peer_label = contact_display(contacts, peer_uid) if peer_uid in contacts else peer_uid
    if not Confirm.ask(f"Delete all messages with {peer_label}?", default=False):
        return
    if not Confirm.ask("Final confirmation: this cannot be undone. Continue?", default=False):
        return
    try:
        peer_pub = contact_pub(contacts, peer_uid)
        if not peer_pub:
            raise RuntimeError("Missing peer key for room derivation.")
        relay.burn(room_id_of(priv, b64d(peer_pub)), my_uid)
        console.print("[dim]Messages deleted from server.[/dim]")
    except Exception as e:
        console.print(f"[red]Burn failed: {e}[/red]")

def _burn_known_rooms(my_uid, my_priv, relay):
    peers = set(load_contacts().keys()) | set(load_seen().keys())
    burned = 0
    failed = 0
    contacts = load_contacts()
    for peer_uid in peers:
        try:
            peer_pub = contact_pub(contacts, peer_uid)
            if not peer_pub:
                failed += 1
                continue
            relay.burn(room_id_of(my_priv, b64d(peer_pub)), my_uid)
            burned += 1
        except:
            failed += 1
    return burned, failed

def _wipe_local_data():
    if CFG_DIR.exists():
        shutil.rmtree(CFG_DIR, ignore_errors=True)

def panic_wipe(my_uid, relay):
    clear()
    console.print()
    console.print(Panel(
        "[bold red]Panic wipe[/bold red]\n\n"
        "This will permanently:\n"
        "1) Delete your local identity, contacts, and local state\n"
        "2) Burn messages in all known rooms on the relay",
        border_style="red"
    ))
    console.print()
    if not Confirm.ask("Are you sure?", default=False):
        return False
    if not Confirm.ask("Final confirmation: execute panic wipe now?", default=False):
        return False

    burned = failed = 0
    if relay.ok():
        burned, failed = _burn_known_rooms(my_uid, relay.auth_priv, relay)
    else:
        console.print("[yellow]Relay unreachable, skipping server-side burns.[/yellow]")

    _wipe_local_data()
    clear()
    console.print("[bold red]Panic wipe complete.[/bold red]")
    console.print(f"[dim]Rooms burned: {burned} | burn failures: {failed}[/dim]")
    console.print("[dim]All local Phantom data has been deleted.[/dim]")
    return True

def cmd_panic():
    priv, _, sign_priv, _, my_uid = unlock()
    relay = Relay(auth_priv=priv, auth_uid=my_uid, sign_priv=sign_priv)
    panic_wipe(my_uid, relay)


def cmd_tor():
    if _tor_running():
        console.print("[green]Tor is running. All traffic is routed through it.[/green]")
    else:
        console.print("Tor is not running.\n")
        console.print(_tor_setup_hint())
        console.print()
        console.print("Phantom still works without Tor, but the relay can see your IP address.")

def _usb_bundle_name():
    return f"phantom-usb-{time.strftime('%Y%m%d-%H%M%S')}"

def _usb_write_scripts(bundle_dir):
    setup_dir = bundle_dir / "setup"
    setup_dir.mkdir(parents=True, exist_ok=True)
    linux_sh = setup_dir / "run-linux.sh"
    mac_sh = setup_dir / "run-macos.sh"
    win_bat = setup_dir / "run-windows.bat"
    readme = setup_dir / "README.txt"

    shell_script = """#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/app"
export PHANTOM_HOME="$ROOT_DIR/data/.phantom"
python3 phantom.py "$@"
"""
    linux_sh.write_text(shell_script, encoding="utf-8")
    mac_sh.write_text(shell_script, encoding="utf-8")
    try:
        os.chmod(linux_sh, 0o755)
        os.chmod(mac_sh, 0o755)
    except OSError:
        pass

    win_bat.write_text(
        "@echo off\r\n"
        "setlocal\r\n"
        "set ROOT_DIR=%~dp0..\\\r\n"
        "cd /d \"%ROOT_DIR%app\"\r\n"
        "set PHANTOM_HOME=%ROOT_DIR%data\\.phantom\r\n"
        "py -3 phantom.py %*\r\n",
        encoding="utf-8",
    )
    readme.write_text(
        "Phantom USB bundle\n\n"
        "Linux:   ./setup/run-linux.sh\n"
        "macOS:   ./setup/run-macos.sh\n"
        "Windows: .\\setup\\run-windows.bat\n\n"
        "The launchers run Phantom with PHANTOM_HOME pointing to data/.phantom\n"
        "so your account files stay on this USB bundle.\n",
        encoding="utf-8",
    )

def cmd_usb(target_dir):
    if not target_dir:
        console.print("[red]Usage: phantom.py usb <target-directory>[/red]")
        return
    dst_root = Path(target_dir).expanduser().resolve()
    if not dst_root.exists() or not dst_root.is_dir():
        console.print("[red]Target path must be an existing directory (USB mount point/path).[/red]")
        return
    if not ID_FILE.exists():
        console.print("[red]No identity found to export.[/red]")
        return
    bundle_dir = dst_root / _usb_bundle_name()
    bundle_app = bundle_dir / "app"
    bundle_data = bundle_dir / "data" / ".phantom"
    bundle_app.mkdir(parents=True, exist_ok=True)
    bundle_data.mkdir(parents=True, exist_ok=True)

    src_app = Path(__file__).resolve()
    shutil.copy2(src_app, bundle_app / "phantom.py")
    req_src = src_app.with_name("requirements.txt")
    if req_src.exists():
        shutil.copy2(req_src, bundle_app / "requirements.txt")

    copied = []
    for src in (ID_FILE, CON_FILE, SET_FILE, SEEN_FILE):
        if src.exists():
            shutil.copy2(src, bundle_data / src.name)
            copied.append(src.name)
    _usb_write_scripts(bundle_dir)
    console.print(f"[green]USB bundle created:[/green] {bundle_dir}")
    console.print(f"[dim]Copied account files:[/dim] {', '.join(copied) if copied else 'none'}")
    console.print("[yellow]Keep this USB secure: it contains your encrypted identity file.[/yellow]")


# --- interactive menu --------------------------------------------------------

_ui_relay_ctx = [None]
_ui_warn_ctx = [True]
_ui_theme_name = [DEFAULT_THEME]
_ui_theme = [THEMES[DEFAULT_THEME]]
_ui_ascii_animal = ["none"]
_ui_motd_profile = [DEFAULT_MOTD_PROFILE]

def _set_ui_context(relay=None):
    _ui_relay_ctx[0] = relay
    st = load_settings()
    _ui_warn_ctx[0] = st.get("show_no_tor_warning", True)
    _ui_theme_name[0] = _theme_pick(st.get("theme", DEFAULT_THEME))
    if _ui_theme_name[0] not in _theme_names():
        _ui_theme_name[0] = DEFAULT_THEME
    _ui_theme[0] = _theme_resolve(_ui_theme_name[0], st)
    _ui_motd_profile[0] = _motd_profile_pick(st.get("motd_profile", DEFAULT_MOTD_PROFILE))
    animal = str(st.get("ascii_animal", "none")).lower()
    _ui_ascii_animal[0] = animal if animal in ASCII_ANIMALS else "none"

def _print_no_tor_warning():
    relay = _ui_relay_ctx[0]
    if not relay or relay.tor or not _ui_warn_ctx[0]:
        return
    th = _ui_theme[0]
    console.print(Panel(
        f"[{th['warn_title']}]Privacy warning[/{th['warn_title']}]\n\n"
        "Tor is not active. Traffic goes directly to the relay.\n"
        "Render/platform logs could expose your IP metadata.\n\n"
        "If you are not using Tor, use a trusted VPN at minimum.\n"
        "[dim]Turn this warning off: menu option 9 > 2 or `python phantom.py warning off`[/dim]",
        border_style=th["warn_border"]
    ))

def clear():
    os.system("cls" if os.name == "nt" else "clear")
    _print_no_tor_warning()

def pause():
    try:
        input("\n  Press Enter to go back...")
    except (KeyboardInterrupt, EOFError):
        pass

SEEN_FILE = CFG_DIR / "seen.json"
SEEN_RECENT_MAX = 300

def _normalize_seen(seen):
    out = {}
    if not isinstance(seen, dict):
        return out
    for peer_uid, entry in seen.items():
        if isinstance(entry, int):
            out[peer_uid] = {"ts": entry, "recent": []}
            continue
        if isinstance(entry, dict):
            ts = entry.get("ts", 0)
            if not isinstance(ts, int):
                ts = 0
            recent = entry.get("recent", [])
            if not isinstance(recent, list):
                recent = []
            recent = [str(x) for x in recent if isinstance(x, str)][:SEEN_RECENT_MAX]
            out[peer_uid] = {"ts": ts, "recent": recent}
    return out

def load_seen():
    if SEEN_FILE.exists():
        with open(SEEN_FILE) as f:
            raw = json.load(f)
        seen = _normalize_seen(raw)
        if seen != raw:
            save_seen(seen)
        return seen
    return {}

def save_seen(seen):
    seen = _normalize_seen(seen)
    with open(SEEN_FILE, "w") as f:
        json.dump(seen, f)
    _safe_chmod(SEEN_FILE, 0o600)

def fetch_unread_counts(my_uid, my_priv, contacts, relay):
    seen = load_seen()
    counts = {}
    for peer_uid in contacts:
        peer_pub = contact_pub(contacts, peer_uid)
        if not peer_pub:
            counts[peer_uid] = 0
            continue
        room = room_id_of(my_priv, b64d(peer_pub))
        skey = session_key(my_priv, b64d(peer_pub), my_uid, peer_uid)
        last_seen_ts = seen.get(peer_uid, {}).get("ts", 0)
        try:
            msgs = relay.fetch(room, since=last_seen_ts, limit=10)
            incoming = 0
            for m in msgs:
                sid = str(m.get("sender_id", ""))
                if not sid:
                    try:
                        env = decode_message_envelope(decrypt(m.get("ciphertext", ""), skey))
                        sid = env[0] if env else ""
                    except Exception:
                        sid = ""
                if sid != my_uid:
                    incoming += 1
            counts[peer_uid] = incoming
        except:
            counts[peer_uid] = 0
    return counts

ghost = r"""
     .-.
   .'   `.
   :g g   :
   : o    `.
  :         ``.
 :             `.
:  :         .   `.
:   :          ` . `.
 `.. :            `. ``;
    `:;             `:'
       :              `.
 jgs    `.              `.     .
          `'`'`'`---..,___`;.-'

"""

cat = r"""
       _                        
       \`*-.                    
        )  _`-.                 
       .  : `. .                
       : _   '  \               
       ; *` _.   `*-._          
       `-.-'          `-.       
         ;       `       `.     
         :.       .        \    
         . \  .   :   .-'   .   
         '  `+.;  ;  '      :   
         :  '  |    ;       ;-. 
         ; '   : :`-:     _.`* ;
      .*' /  .*' ; .*`- +'  `*' 
[bug] `*-*   `*-*  `*-*'
"""

dog = r"""
                _,)
        _..._.-;-'
     .-'     `(
    /      ;   \
   ;.' ;`  ,;  ;
  .'' ``. (  \ ;
 / f_ _L \ ;  )\
 \/|` '|\/;; <;/
((; \_/  (()       Felix Lee
     "
"""

penguin = r"""
             . --- .
           /        \
          |  O  _  O |
          |  ./   \. |
          /  `-._.-'  \
        .' /         \ `.
    .-~.-~/           \~-.~-.
.-~ ~    |             |    ~ ~-.
`- .     |             |     . -'
     ~ - |             | - ~
         \             /
       ___\           /___
       ~;_  >- . . -<  _i~
          `'         `'
"""

bear = r"""
  _      _
 : `.--.' ;              _....,_
 .'      `.      _..--'"'       `-._
:          :_.-'"                  .`.
:  6    6  :                     :  '.;
:          :                      `..';
`: .----. :'                          ;
  `._Y _.'               '           ;
    'U'      .'          `.         ;
       `:   ;`-..___       `.     .'`.
       _:   :  :    ```"''"'``.    `.  `.
     .'     ;..'            .'       `.'`
    `.......'              `........-'`
"""
GHOST_ASCII = ghost.strip("\n")
CAT_ASCII = cat.strip("\n")
BEAR_ASCII = bear.strip("\n")
DOG_ASCII = dog.strip("\n")
PENGUIN_ASCII = penguin.strip("\n")

ASCII_ANIMALS = {
    "none": "",
    "cat": CAT_ASCII,
    "dog": DOG_ASCII,
    "penguin": PENGUIN_ASCII,
    "bear": BEAR_ASCII,
    "ghost": GHOST_ASCII,
}



def badge(n):
    if n <= 0:
        return ""
    return f" [bold red]({'+'+'9' if n > 9 else n})[/bold red]"

def mark_seen(peer_uid):
    seen = load_seen()
    entry = seen.setdefault(peer_uid, {"ts": 0, "recent": []})
    entry["ts"] = max(entry.get("ts", 0), (int(time.time()) // 60) * 60)
    save_seen(seen)

def draw_menu(uid, tor, unread=None):
    clear()
    motd = get_motd() or ""
    th = _ui_theme[0]
    console.print()
    console.print(Panel(
        f"[bold {th['title']}]Phantom {APP_VERSION}[/bold {th['title']}]  [dim]{'via Tor' if tor else 'direct'}[/dim]"
        f" | [dim]theme: {_ui_theme_name[0]}[/dim]"
        f" | [dim]motd: {_ui_motd_profile[0]}[/dim]\n"
        f"[dim]{motd}[/dim]\n\n"
        f"[dim]uid:  [/dim][{th['accent']}]{uid}[/{th['accent']}]",
        border_style=th["panel_border"]
    ))
    console.print()
    total = sum(unread.values()) if unread else 0
    msg_label = "Message a contact" + (badge(total) if unread else "")
    menu_block = Group(
        f"  [{th['section']}]Chat[/{th['section']}]",
        f"  [bold]1[/bold]  {msg_label}",
        "  [bold]2[/bold]  Add a contact",
        "  [bold]3[/bold]  Contacts",
        "  [bold]4[/bold]  My uid",
        "",
        f"  [{th['section']}]Conversation[/{th['section']}]",
        "  [bold]5[/bold]  Delete messages",
        "  [bold]6[/bold]  Set nickname",
        "  [bold]7[/bold]  Remove contact",
        "",
        f"  [{th['section']}]System[/{th['section']}]",
        "  [bold]8[/bold]  Tor status",
        "  [bold]9[/bold]  Settings",
        "",
        f"  [{th['section']}]Danger / Exit[/{th['section']}]",
        f"  [bold]10[/bold]  [{th['danger']}]Panic wipe[/{th['danger']}]",
        "  [bold]0[/bold]  Quit",
    )
    animal = _ui_ascii_animal[0]
    art = ASCII_ANIMALS.get(animal, "")
    if animal != "none" and art:
        animal_panel = Panel(art, border_style=th["cat_border"], title=f"{animal}s support privacy", expand=False)
        console.print(Columns([menu_block, animal_panel], equal=False, expand=True))
    else:
        console.print(menu_block)
    console.print()

_notify_lock      = threading.Lock()
_notify_unread: dict = {}
_notify_stop      = threading.Event()
_current_chat_peer: list = [None]

def _start_notifier(my_uid, my_priv, relay):
    def _run():
        while not _notify_stop.is_set():
            _notify_stop.wait(5)
            if _notify_stop.is_set():
                break
            try:
                contacts_now = load_contacts()
                if not contacts_now:
                    continue
                new_counts = fetch_unread_counts(my_uid, my_priv, contacts_now, relay)
                with _notify_lock:
                    for peer, count in new_counts.items():
                        prev = _notify_unread.get(peer, 0)
                        if count > prev:
                            short = short_contact_display(contacts_now, peer)
                            currently_in_chat = _current_chat_peer[0] is not None
                            is_this_peer = _current_chat_peer[0] == peer
                            if is_this_peer:
                                pass
                            elif currently_in_chat:
                                console.print(f"\n  [bold yellow]! new message from {short}[/bold yellow]")
                            else:
                                console.print(f"\n  [bold yellow]! new message from {short}[/bold yellow]  [dim](press Enter)[/dim]")
                    _notify_unread.update(new_counts)
            except:
                pass
    threading.Thread(target=_run, daemon=True).start()

def _stop_notifier():
    _notify_stop.set()

def interactive_menu(priv, pub, uid, relay):
    _set_ui_context(relay)
    contacts = load_contacts()
    unread = fetch_unread_counts(uid, priv, contacts, relay) if contacts else {}
    with _notify_lock:
        _notify_unread.update(unread)

    while True:
        contacts = load_contacts()
        with _notify_lock:
            unread = dict(_notify_unread)
        draw_menu(uid, relay.tor, unread)

        try:
            choice = input("  > ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            clear()
            break

        if choice == "1":
            clear()
            if not contacts:
                console.print("\n  No contacts yet. Add one first.")
                pause()
                continue
            console.print("\n  Your contacts:\n")
            contact_list = list(contacts.keys())
            t = Table(show_lines=True, border_style="dim", show_header=False)
            t.add_column("", style="dim")
            t.add_column("Name", style="magenta")
            t.add_column("UID", style="cyan")
            t.add_column("Unread", style="red")
            for i, c in enumerate(contact_list, 1):
                unread_n = unread.get(c, 0)
                t.add_row(str(i), contact_nick(contacts, c) or "-", c, f"+{unread_n}" if unread_n > 0 else "")
            console.print(t)
            console.print()
            try:
                pick = input("  Enter number or uid: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            peer_uid = resolve_contact_pick(contacts, pick, contact_list)
            if not peer_uid:
                console.print("  [red]Not found.[/red]")
                pause()
                continue
            mark_seen(peer_uid)
            with _notify_lock:
                _notify_unread[peer_uid] = 0
            cmd_chat(peer_uid, priv=priv, pub=pub, my_uid=uid, relay=relay)
            with _notify_lock:
                unread = dict(_notify_unread)

        elif choice == "2":
            clear()
            console.print("\n  [bold]Add a contact[/bold]\n")
            try:
                peer_uid = input("  Paste their uid: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            if not peer_uid:
                continue
            if not relay.ok():
                console.print("\n  [red]Cannot reach relay.[/red]")
                pause()
                continue
            console.print("  Looking up uid...")
            pub_b64 = relay.pubkey(peer_uid)
            if not pub_b64:
                console.print("  [red]No user found with that uid.[/red]")
                pause()
                continue
            try:
                fp = ensure_contact_key_safe(contacts, peer_uid, pub_b64)
            except RuntimeError as e:
                console.print(f"  [red]{e}[/red]")
                pause()
                continue
            save_contacts(contacts)
            relay.ke_push(uid, peer_uid, b64e(pub), room_id_of(priv, b64d(pub_b64)))
            console.print("  [green]Contact added.[/green]")
            console.print(f"  [dim]Fingerprint:[/dim] {fp}")
            if not contact_verified_fp(contacts, peer_uid):
                console.print("  [yellow]Not verified yet.[/yellow]")
                if Confirm.ask("  Trust this fingerprint now (after out-of-band check)?", default=False):
                    trust_contact_key(contacts, peer_uid)
                    save_contacts(contacts)
                    console.print("  [green]Contact fingerprint trusted.[/green]")
                else:
                    console.print(f"  [dim]You can verify later with:[/dim] [bold]python phantom.py verify {peer_uid}[/bold]")
            pause()

        elif choice == "3":
            clear()
            console.print("\n  [bold]Contacts[/bold]\n")
            contacts = load_contacts()
            if not contacts:
                console.print("  No contacts yet.")
            else:
                t = Table(show_lines=True, border_style="dim", show_header=False)
                t.add_column("", style="dim")
                t.add_column("Name", style="magenta")
                t.add_column("UID", style="cyan")
                t.add_column("Verified", style="green")
                for i, c in enumerate(contacts, 1):
                    t.add_row(str(i), contact_nick(contacts, c) or "-", c, "yes" if contact_verified_fp(contacts, c) else "no")
                console.print(t)
            pause()

        elif choice == "4":
            clear()
            console.print()
            console.print(Panel(
                f"[bold]Your uid[/bold]\n\n[cyan]{uid}[/cyan]\n\n"
                "[dim]Share this with people who want to message you.[/dim]",
                border_style="cyan"
            ))
            pause()

        elif choice == "5":
            clear()
            console.print("\n  [bold]Delete messages[/bold]\n")
            contacts = load_contacts()
            if not contacts:
                console.print("  No contacts.")
                pause()
                continue
            contact_list = list(contacts.keys())
            for i, c in enumerate(contact_list, 1):
                console.print(f"  [bold]{i}[/bold]  {contact_display(contacts, c)}")
            console.print()
            try:
                pick = input("  Enter number or uid: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            peer_uid = resolve_contact_pick(contacts, pick, contact_list)
            if not peer_uid:
                console.print("  [red]Not found.[/red]")
                pause()
                continue
            console.print()
            if Confirm.ask(f"  Delete all messages with {contact_display(contacts, peer_uid)}?", default=False):
                if Confirm.ask("  Final confirmation: delete now?", default=False):
                    try:
                        peer_pub = contact_pub(contacts, peer_uid)
                        if not peer_pub:
                            raise RuntimeError("Missing peer key for room derivation.")
                        relay.burn(room_id_of(priv, b64d(peer_pub)), uid)
                        console.print("  [dim]Messages deleted.[/dim]")
                    except Exception as e:
                        console.print(f"  [red]Burn failed: {e}[/red]")
                    pause()

        elif choice == "8":
            clear()
            console.print()
            if relay.tor:
                console.print(Panel(
                    "[green]Tor is active.[/green]\n\n"
                    "All traffic is routed through the Tor network.\n"
                    "The relay cannot see your real IP address.",
                    border_style="green", title="Tor Status"
                ))
            else:
                console.print(Panel(
                    "Tor is not running.\n\n"
                    "Your IP address is visible to the relay server.\n\n"
                    f"[dim]{_tor_setup_hint()}\n\n"
                    "Restart Phantom after enabling Tor.[/dim]",
                    border_style="yellow", title="Tor Status"
                ))
            pause()

        elif choice == "6":
            clear()
            console.print("\n  [bold]Set nickname[/bold]\n")
            contacts = load_contacts()
            if not contacts:
                console.print("  No contacts.")
                pause()
                continue
            contact_list = list(contacts.keys())
            for i, c in enumerate(contact_list, 1):
                console.print(f"  [bold]{i}[/bold]  {contact_display(contacts, c)}")
            console.print()
            try:
                pick = input("  Enter number or uid: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            peer_uid = resolve_contact_pick(contacts, pick, contact_list)
            if not peer_uid:
                console.print("  [red]Not found.[/red]")
                pause()
                continue
            current = contact_nick(contacts, peer_uid)
            prompt = f"  Nickname for {peer_uid}"
            if current:
                prompt += f" [current: {current}]"
            prompt += " (blank to clear): "
            try:
                nick = input(prompt).strip()
            except (KeyboardInterrupt, EOFError):
                continue
            upsert_contact(contacts, peer_uid, nickname=nick)
            save_contacts(contacts)
            console.print("  [green]Nickname saved.[/green]")
            pause()

        elif choice == "10":
            if panic_wipe(uid, relay):
                time.sleep(0.8)
                break

        elif choice == "9":
            while True:
                clear()
                st = load_settings()
                current_theme = st.get("theme", DEFAULT_THEME)
                current_animal = st.get("ascii_animal", "none")
                current_motd = st.get("motd_profile", DEFAULT_MOTD_PROFILE)
                console.print("  [bold]Settings[/bold]\n")
                console.print("  [bold]1[/bold]  Startup options")
                console.print(f"       [dim]Current:[/dim] {'enabled' if startup_status() else 'disabled'}")
                console.print("  [bold]2[/bold]  No-Tor warning")
                console.print(f"       [dim]Current:[/dim] {'on' if st.get('show_no_tor_warning', True) else 'off'}")
                console.print("  [bold]3[/bold]  Update checks")
                console.print(f"       [dim]Current:[/dim] {'on' if st.get('update_checks', True) else 'off'}")
                console.print("  [bold]4[/bold]  Theme + ASCII + MOTD")
                console.print(f"       [dim]Current:[/dim] theme={current_theme}, animal={current_animal}, motd={current_motd}")
                console.print("  [bold]5[/bold]  Export account to USB\n")
                console.print("  [bold]0[/bold]  Back\n")
                try:
                    mode = input("  settings > ").strip().lower()
                except (KeyboardInterrupt, EOFError):
                    break
                if mode in ("", "0"):
                    break
                if mode == "1":
                    clear()
                    console.print("\n  [bold]Startup options[/bold]\n")
                    console.print(f"  Current: [cyan]{'enabled' if startup_status() else 'disabled'}[/cyan]\n")
                    console.print("  [bold]1[/bold]  Enable startup")
                    console.print("  [bold]2[/bold]  Disable startup")
                    console.print("  [bold]3[/bold]  Status")
                    console.print()
                    try:
                        act = input("  > ").strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        continue
                    if act == "1":
                        cmd_startup("enable")
                    elif act == "2":
                        cmd_startup("disable")
                    elif act == "3":
                        cmd_startup("status")
                    else:
                        console.print("  [red]Invalid option.[/red]")
                    pause()
                    continue
                if mode == "2":
                    clear()
                    console.print("\n  [bold]No-Tor warning[/bold]\n")
                    console.print(f"  Current: [cyan]{'on' if st.get('show_no_tor_warning', True) else 'off'}[/cyan]\n")
                    console.print("  [bold]1[/bold]  Turn on")
                    console.print("  [bold]2[/bold]  Turn off")
                    console.print("  [bold]3[/bold]  Status")
                    console.print()
                    try:
                        act = input("  > ").strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        continue
                    if act == "1":
                        cmd_warning("on")
                    elif act == "2":
                        cmd_warning("off")
                    elif act == "3":
                        cmd_warning("status")
                    else:
                        console.print("  [red]Invalid option.[/red]")
                    _set_ui_context(relay)
                    pause()
                    continue
                if mode == "3":
                    clear()
                    console.print("\n  [bold]Update checks[/bold]\n")
                    console.print(f"  Current: [cyan]{'on' if st.get('update_checks', True) else 'off'}[/cyan]\n")
                    console.print("  [bold]1[/bold]  Turn on")
                    console.print("  [bold]2[/bold]  Turn off")
                    console.print("  [bold]3[/bold]  Status")
                    console.print("  [bold]4[/bold]  Reset key pin")
                    console.print()
                    try:
                        act = input("  > ").strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        continue
                    if act == "1":
                        cmd_updates("on")
                    elif act == "2":
                        cmd_updates("off")
                    elif act == "3":
                        cmd_updates("status")
                    elif act == "4":
                        cmd_updates("reset-pin")
                    else:
                        console.print("  [red]Invalid option.[/red]")
                    pause()
                    continue
                if mode == "4":
                    clear()
                    names = _theme_names()
                    animals = ["none", "cat", "dog", "penguin", "bear", "ghost"]
                    motd_profiles = _motd_profiles()
                    console.print("\n  [bold]Theme + ASCII + MOTD[/bold]\n")
                    console.print(f"  Theme: [cyan]{current_theme}[/cyan]")
                    console.print(f"  ASCII mascot: [cyan]{current_animal}[/cyan]")
                    console.print(f"  MOTD profile: [cyan]{current_motd}[/cyan]\n")
                    console.print("  [bold]1[/bold]  Set theme")
                    console.print("  [bold]2[/bold]  Set ASCII mascot")
                    console.print("  [bold]3[/bold]  Edit custom theme")
                    console.print("  [bold]4[/bold]  Set MOTD profile")
                    console.print("  [bold]5[/bold]  Edit custom MOTDs")
                    console.print("  [bold]0[/bold]  Back\n")
                    try:
                        sub = input("  > ").strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        continue
                    if sub in ("", "0"):
                        continue
                    if sub == "1":
                        console.print()
                        for i, name in enumerate(names, 1):
                            tag = " [dim](current)[/dim]" if name == current_theme else ""
                            console.print(f"  [bold]{i}[/bold]  {name}{tag}")
                        console.print("  [bold]0[/bold]  Back\n")
                        try:
                            pick = input("  theme > ").strip().lower()
                        except (KeyboardInterrupt, EOFError):
                            continue
                        if pick in ("", "0"):
                            continue
                        if pick.isdigit() and 1 <= int(pick) <= len(names):
                            cmd_theme(names[int(pick) - 1])
                        else:
                            cmd_theme(pick)
                        _set_ui_context(relay)
                        pause()
                        continue
                    if sub == "2":
                        console.print()
                        for i, name in enumerate(animals, 1):
                            tag = " [dim](current)[/dim]" if name == current_animal else ""
                            console.print(f"  [bold]{i}[/bold]  {name}{tag}")
                        console.print("  [bold]0[/bold]  Back\n")
                        try:
                            pick = input("  animal > ").strip().lower()
                        except (KeyboardInterrupt, EOFError):
                            continue
                        if pick in ("", "0"):
                            continue
                        if pick.isdigit() and 1 <= int(pick) <= len(animals):
                            chosen = animals[int(pick) - 1]
                        else:
                            chosen = pick
                        if chosen not in animals:
                            console.print(f"  [red]Unknown animal: {chosen}[/red]")
                            pause()
                            continue
                        st["ascii_animal"] = chosen
                        save_settings(st)
                        _set_ui_context(relay)
                        console.print(f"  [green]ASCII animal set:[/green] {chosen}")
                        pause()
                        continue
                    if sub == "3":
                        custom = _theme_custom_norm(st.get("theme_custom", {}))
                        fields = [
                            ("title", "Title color/style"),
                            ("panel_border", "Panel border"),
                            ("section", "Section label style"),
                            ("accent", "Accent color"),
                            ("cat_border", "Animal panel border"),
                            ("warn_border", "Warning border"),
                            ("warn_title", "Warning title style"),
                            ("danger", "Danger style"),
                        ]
                        console.print("\n  [bold]Edit custom theme[/bold]")
                        console.print("  [dim]Leave blank to keep current value.[/dim]\n")
                        for key, label in fields:
                            try:
                                val = input(f"  {label} [{custom[key]}]: ").strip()
                            except (KeyboardInterrupt, EOFError):
                                val = ""
                            if val:
                                custom[key] = val
                        st["theme_custom"] = custom
                        st["theme"] = "custom"
                        save_settings(st)
                        _set_ui_context(relay)
                        console.print("  [green]Custom theme saved and activated.[/green]")
                        pause()
                        continue
                    if sub == "4":
                        console.print()
                        for i, name in enumerate(motd_profiles, 1):
                            tag = " [dim](current)[/dim]" if name == current_motd else ""
                            console.print(f"  [bold]{i}[/bold]  {name}{tag}")
                        console.print("  [bold]0[/bold]  Back\n")
                        try:
                            pick = input("  motd > ").strip().lower()
                        except (KeyboardInterrupt, EOFError):
                            continue
                        if pick in ("", "0"):
                            continue
                        if pick.isdigit() and 1 <= int(pick) <= len(motd_profiles):
                            chosen = motd_profiles[int(pick) - 1]
                        else:
                            chosen = pick
                        if chosen not in motd_profiles:
                            console.print(f"  [red]Unknown MOTD profile: {pick}[/red]")
                            pause()
                            continue
                        st["motd_profile"] = chosen
                        st["motd_locked_profile"] = ""
                        st["motd_locked_line"] = ""
                        save_settings(st)
                        _set_ui_context(relay)
                        console.print(f"  [green]MOTD profile set:[/green] {chosen}")
                        pause()
                        continue
                    if sub == "5":
                        custom_lines = _motd_custom_norm(st.get("motd_custom_lines", []))
                        console.print("\n  [bold]Edit custom MOTDs[/bold]\n")
                        if custom_lines:
                            console.print("  Current custom MOTDs:")
                            for i, line in enumerate(custom_lines, 1):
                                console.print(f"    [bold]{i}[/bold]. {line}")
                        else:
                            console.print("  [dim]No custom MOTDs saved yet.[/dim]")
                        console.print("\n  Enter lines separated by [bold]|[/bold].")
                        console.print("  Type [bold]clear[/bold] to remove all custom MOTDs.")
                        try:
                            raw = input("  custom motd > ").strip()
                        except (KeyboardInterrupt, EOFError):
                            continue
                        if not raw:
                            continue
                        if raw.lower() == "clear":
                            st["motd_custom_lines"] = []
                            if st.get("motd_profile") == CUSTOM_MOTD_PROFILE:
                                st["motd_locked_profile"] = ""
                                st["motd_locked_line"] = ""
                            save_settings(st)
                            _set_ui_context(relay)
                            console.print("  [green]Custom MOTDs cleared.[/green]")
                            pause()
                            continue
                        lines = _motd_custom_norm(raw.split("|"))
                        if not lines:
                            console.print("  [red]No valid MOTD lines found.[/red]")
                            pause()
                            continue
                        st["motd_custom_lines"] = lines
                        st["motd_profile"] = CUSTOM_MOTD_PROFILE
                        st["motd_locked_profile"] = ""
                        st["motd_locked_line"] = ""
                        save_settings(st)
                        _set_ui_context(relay)
                        console.print(f"  [green]Saved {len(lines)} custom MOTD line(s) and switched profile to custom.[/green]")
                        pause()
                        continue
                    console.print("  [red]Invalid option.[/red]")
                    pause()
                    continue
                if mode == "5":
                    clear()
                    console.print("\n  [bold]Export account to USB[/bold]\n")
                    console.print("  This creates a portable bundle with app + account files.")
                    console.print("  Example paths:")
                    console.print("    Linux/macOS: /media/USB or /Volumes/USB")
                    console.print("    Windows: E:\\\n")
                    try:
                        target = input("  USB target directory: ").strip()
                    except (KeyboardInterrupt, EOFError):
                        continue
                    if not target:
                        continue
                    cmd_usb(target)
                    pause()
                    continue
                console.print("  [red]Invalid option.[/red]")
                pause()
                continue

        elif choice == "7":
            clear()
            console.print("\n  [bold]Remove contact[/bold]\n")
            contacts = load_contacts()
            if not contacts:
                console.print("  No contacts.")
                pause()
                continue
            contact_list = list(contacts.keys())
            t = Table(show_lines=True, border_style="dim", show_header=False)
            t.add_column("", style="dim")
            t.add_column("Name", style="magenta")
            t.add_column("UID", style="cyan")
            for i, c in enumerate(contact_list, 1):
                t.add_row(str(i), contact_nick(contacts, c) or "-", c)
            console.print(t)
            console.print()
            try:
                pick = input("  Enter number or uid: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            peer_uid = resolve_contact_pick(contacts, pick, contact_list)
            if not peer_uid:
                console.print("  [red]Not found.[/red]")
                pause()
                continue
            cmd_remove(peer_uid, my_uid=uid, relay=relay, my_priv=priv)
            pause()

        elif choice == "0":
            clear()
            break

        else:
            pass


# --- entry point -------------------------------------------------------------

HELP = """
[bold]Phantom[/bold] — private encrypted messaging

[bold]Commands:[/bold]
  [cyan]update[/cyan]             Check for a newer phantom.py version
  [cyan]register[/cyan]           Create a new identity
  [cyan]whoami[/cyan]             Show your uid
  [cyan]add[/cyan] [dim]<uid>[/dim]          Add a contact by their uid
  [cyan]verify[/cyan] [dim]<uid> [--force][/dim] Verify/trust a contact key fingerprint
  [cyan]nick[/cyan] [dim]<uid> <name>[/dim]   Set a local nickname for a contact
  [cyan]contacts[/cyan]           List your contacts
  [cyan]remove[/cyan] [dim]<uid>[/dim]       Burn messages then remove contact
  [cyan]chat[/cyan] [dim]<uid>[/dim]         Chat with a contact
  [cyan]burn[/cyan] [dim]<uid>[/dim]         Delete all messages with a contact
  [cyan]startup[/cyan] [dim]<action>[/dim]   Manage startup: enable|disable|status
  [cyan]warning[/cyan] [dim]<mode>[/dim]     No-Tor warning: on|off|status
  [cyan]updates[/cyan] [dim]<mode>[/dim]     Update checks: on|off|status|reset-pin
  [cyan]theme[/cyan] [dim]<mode>[/dim]       Theme: list|status|<name>
  [cyan]usb[/cyan] [dim]<path>[/dim]          Export portable bundle to USB/path
  [cyan]panic[/cyan]            Panic wipe local data + burn known rooms
  [cyan]tor[/cyan]                Check Tor status

[dim]Run without arguments to open the interactive menu.[/dim]
"""

def main():
    CFG_DIR.mkdir(mode=0o700, exist_ok=True)

    args = sys.argv[1:]

    if not args:
        if not ID_FILE.exists():
            first_run_wizard()
            return

        clear()
        try:
            pw = getpass.getpass("Password: ")
            priv, pub, sign_priv, sign_pub = load_identity(str(ID_FILE), pw)
            if not sign_priv or not sign_pub:
                console.print("[red]Identity missing signing key. Please re-register with the latest client.[/red]")
                return
            uid = uid_of(pub)
        except ValueError:
            console.print("[red]Wrong password.[/red]")
            return

        relay = Relay(auth_priv=priv, auth_uid=uid, sign_priv=sign_priv)
        _set_ui_context(relay)
        maybe_prompt_update()
        _start_notifier(uid, priv, relay)
        try:
            interactive_menu(priv, pub, uid, relay)
        finally:
            _stop_notifier()
            _set_ui_context(None)
        return

    if args[0] in ("-h", "--help", "help"):
        console.print(HELP)
        return

    cmd  = args[0]
    arg1 = args[1] if len(args) > 1 else None

    match cmd:
        case "update":
            maybe_prompt_update(force=True)
        case "register":
            cmd_register()
        case "whoami":
            cmd_whoami()
        case "add":
            if not arg1:
                console.print("[red]Usage: phantom.py add <uid>[/red]")
                sys.exit(1)
            cmd_add(arg1)
        case "verify":
            if not arg1:
                console.print("[red]Usage: phantom.py verify <uid> [--force][/red]")
                sys.exit(1)
            force = "--force" in args[2:]
            cmd_verify(arg1, force=force)
        case "contacts":
            cmd_contacts()
        case "remove":
            if not arg1:
                console.print("[red]Usage: phantom.py remove <uid>[/red]")
                sys.exit(1)
            cmd_remove(arg1)
        case "nick":
            if len(args) < 3:
                console.print("[red]Usage: phantom.py nick <uid> <nickname>[/red]")
                sys.exit(1)
            cmd_nick(arg1, " ".join(args[2:]))
        case "chat":
            if not arg1:
                console.print("[red]Usage: phantom.py chat <uid>[/red]")
                sys.exit(1)
            cmd_chat(arg1)
        case "burn":
            if not arg1:
                console.print("[red]Usage: phantom.py burn <uid>[/red]")
                sys.exit(1)
            cmd_burn(arg1)
        case "tor":
            cmd_tor()
        case "startup":
            cmd_startup(arg1 or "status")
        case "warning":
            cmd_warning(arg1 or "status")
        case "updates":
            cmd_updates(arg1 or "status")
        case "theme":
            cmd_theme(arg1 or "status")
        case "usb":
            if len(args) < 2:
                console.print("[red]Usage: phantom.py usb <target-directory>[/red]")
                sys.exit(1)
            cmd_usb(" ".join(args[1:]))
        case "panic":
            cmd_panic()
        case _:
            console.print(f"[red]Unknown command: {cmd}[/red]")
            console.print(HELP)

if __name__ == "__main__":
    main()
