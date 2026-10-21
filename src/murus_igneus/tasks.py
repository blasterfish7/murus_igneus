"""Bounded background tasks for optional management modules. SPDX-License-Identifier: MIT."""
import copy
import secrets
import threading
import time


class Task:
    def __init__(self):
        self.lock = threading.RLock()
        self.value = None

    def status(self):
        with self.lock:
            return copy.deepcopy(self.value)

    def start(self, action):
        with self.lock:
            if self.value and self.value['state'] == 'running':
                raise ValueError('Operazione già in corso')
            ident = secrets.token_hex(16)
            self.value = {'id': ident, 'state': 'running', 'started': time.time()}

        def worker():
            try:
                result = action()
                with self.lock:
                    self.value.update(state='succeeded', result=result, finished=time.time())
            except Exception as exc:
                with self.lock:
                    self.value.update(state='failed', error=str(exc)[:600], finished=time.time())
        threading.Thread(target=worker, daemon=True).start()
        return {'id': ident}
