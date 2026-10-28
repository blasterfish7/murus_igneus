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

# The appliance uses the root shadow entry as the single password authority.
# A legacy web password is accepted only until the required migration completes.
def credentials(state):
    path = Path(state) / 'credentials.json'
    return json.loads(path.read_text()) if path.exists() else {'system_root': False}


def shadow_record(path=Path('/etc/shadow')):
    for line in Path(path).read_text().splitlines():
        values = line.split(':')
        if values[0] == 'root' and len(values) == 9:
            return values
    raise ValueError('Credenziali console root non disponibili')


def password_hash(value, setting):
    import ctypes
    import ctypes.util
    with LOCK:
        library = ctypes.CDLL(ctypes.util.find_library('crypt') or 'libcrypt.so.1')
        library.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        library.crypt.restype = ctypes.c_char_p
        result = library.crypt(value.encode('utf-8'), setting.encode('ascii'))
        if not result or result.startswith(b'*'):
            raise ValueError('Formato password console non supportato')
        return result.decode('ascii')


def password_status(state, shadow=Path('/etc/shadow')):
    with LOCK:
        config = credentials(state)
        system = config.get('system_root') is True
        required = config.get('must_change') is True
        if system:
            record = shadow_record(shadow)
            required = required or record[2] == '0' or bool(record[2] and record[4] and int(record[2]) + int(record[4]) <= int(time.time() // 86400))
        return {'password_change_required': required, 'shared_console_password': system}


def check_password(state, value, shadow=Path('/etc/shadow')):
    with LOCK:
        if not isinstance(value, str) or '\x00' in value:
            return False
        if credentials(state).get('system_root') is not True:
            expected = (Path(state) / 'admin.password').read_text().strip()
            return hmac.compare_digest(hashlib.sha256(value.encode()).digest(), hashlib.sha256(expected.encode()).digest())
        record = shadow_record(shadow)
        encoded = record[1]
        if not encoded or encoded.startswith(('!', '*')):
            return False
        if record[7] and int(record[7]) <= int(time.time() // 86400):
            return False
        return hmac.compare_digest(password_hash(value, encoded), encoded)


def initialize_credentials(state):
    state = Path(state)
    if not (state / 'credentials.json').exists():
        # Existing installations migrate explicitly on first login; no console
        # password is modified merely by installing or starting the package.
        write(state / 'credentials.json', {'system_root': False, 'must_change': True})
    if credentials(state).get('system_root') is not True and not (state / 'admin.password').exists():
        path = state / 'admin.password'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write('igneus\n')


def change_password(state, value, confirmation, shadow=Path('/etc/shadow'), runner=None):
    import subprocess
    if not isinstance(value, str) or value != confirmation:
        raise ValueError('Le due password non coincidono')
    if not 8 <= len(value) <= 128 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Usare da 8 a 128 caratteri, senza caratteri di controllo')
    if runner is None:
        runner = subprocess.run
    state = Path(state)
    with LOCK:
        if check_password(state, value, shadow):
            raise ValueError('Scegliere una password diversa da quella corrente')
        old_config = credentials(state)
        old_shadow = shadow_record(shadow)[1]
        encoded = password_hash(value, '$6$rounds=200000$' + secrets.token_hex(8) + '$')
        # Switch authority before the atomic system update. A crash therefore
        # never leaves two different active passwords: root remains canonical.
        write(state / 'credentials.json', {'system_root': True, 'must_change': True})
        try:
            runner(['chpasswd', '-e'], input='root:' + encoded + '\n', text=True, capture_output=True, check=True, timeout=20)
        except Exception:
            if shadow_record(shadow)[1] == old_shadow:
                write(state / 'credentials.json', old_config)
            raise ValueError('Cambio password non completato. Verificare dalla console; riprovare con la password console attuale.') from None
        if shadow_record(shadow)[1] != encoded:
            raise ValueError('Password console non verificata: accesso di gestione ancora limitato al cambio password')
        write(state / 'credentials.json', {'system_root': True, 'must_change': False})
        (state / 'admin.password').unlink(missing_ok=True)
        SESSIONS.clear(); PENDING.clear()
        return {'ok': True, 'shared_console_password': True, 'reauthenticate': True}
