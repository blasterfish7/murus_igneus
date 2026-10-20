# Security policy

**Experimental development software; do not deploy in production.**

On first start the management service generates a random password for the `admin` user and stores it in `/etc/murus_igneus/admin.password` (readable only by root: read it with `cat`). Replacing the file's contents changes the password immediately. The password is never written to the logs; only its location is.

Installations created by earlier builds may still use the publicly known lab password `igneus`. The web interface shows a warning, and the service logs one at start-up, until you replace it.

Never expose the management listener to untrusted networks. Do not commit secrets, production FortiGate backups, keys or certificates.

Please report potential vulnerabilities privately, using GitHub private vulnerability reporting if enabled.
