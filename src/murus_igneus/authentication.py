"""TOTP enrollment, replay protection and expiring management sessions. SPDX-License-Identifier: MIT."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import struct
import threading
import time
from urllib.parse import urlencode

LOCK = threading.RLock()
SESSIONS = {}
ATTEMPTS = {}
PENDING = {}


def write(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream)
    temporary.chmod(0o600); temporary.replace(path)


def read(state):
    path = Path(state) / 'mfa.json'
    return json.loads(path.read_text()) if path.exists() else None


def code(secret, step):
    digest = hmac.new(base64.b32decode(secret), struct.pack('>Q', step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)


def verify(secret, value, last=-1, now=None):
    if not isinstance(value, str) or len(value) != 6 or not value.isascii() or not value.isdecimal():
        raise ValueError('Codice TOTP non valido')
    step = int((time.time() if now is None else now) // 30)
    for candidate in (step, step - 1, step + 1):
        if candidate > last and hmac.compare_digest(code(secret, candidate), value):
            return candidate
    raise ValueError('Codice TOTP errato, scaduto o già utilizzato')


def limit(peer):
    now = time.monotonic()
    # Bound storage even for many source addresses.
    for key in list(ATTEMPTS):
        ATTEMPTS[key] = [t for t in ATTEMPTS[key] if now - t < 60]
        if not ATTEMPTS[key]:
            del ATTEMPTS[key]
    if len(ATTEMPTS) >= 1024 and peer not in ATTEMPTS:
        raise ValueError('Troppe richieste di autenticazione')
    attempts = ATTEMPTS.setdefault(peer, [])
    if len(attempts) >= 5:
        raise ValueError('Troppi tentativi: attendere un minuto')
    attempts.append(now)


def valid_session(token, peer):
    with LOCK:
        now = time.monotonic()
        for key in list(SESSIONS):
            if SESSIONS[key][1] <= now:
                del SESSIONS[key]
        return bool(token and token in SESSIONS and SESSIONS[token][0] == peer)


def enroll(state):
    with LOCK:
        secret = base64.b32encode(secrets.token_bytes(20)).decode()
        PENDING[str(state)] = (secret, time.monotonic() + 300)
        uri = 'otpauth://totp/Murus%20Igneus:admin?' + urlencode({'secret': secret, 'issuer': 'Murus Igneus', 'algorithm': 'SHA1', 'digits': 6, 'period': 30})
        return {'secret': secret, 'uri': uri, 'expires_in': 300}


def confirm(state, value, peer):
    with LOCK:
        limit(peer)
        pending = PENDING.get(str(state))
        if not pending or pending[1] < time.monotonic():
            raise ValueError('Registrazione TOTP scaduta: ricominciare')
        step = verify(pending[0], value)
        write(Path(state) / 'mfa.json', {'secret': pending[0], 'last': step})
        del PENDING[str(state)]; SESSIONS.clear()
        return session(peer)


def session(peer):
    token = secrets.token_urlsafe(32)
    if len(SESSIONS) >= 256:
        del SESSIONS[next(iter(SESSIONS))]
    SESSIONS[token] = (peer, time.monotonic() + 900)
    return token


def authenticate(state, value, peer):
    with LOCK:
        limit(peer)
        current = read(state)
        if not current:
            raise ValueError('TOTP non configurato')
        current['last'] = verify(current['secret'], value, current['last'])
        write(Path(state) / 'mfa.json', current)
        return session(peer)


def disable(state, value, peer):
    with LOCK:
        authenticate(state, value, peer)
        (Path(state) / 'mfa.json').unlink()
        SESSIONS.clear()
