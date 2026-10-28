# SPDX-License-Identifier: MIT
# Show the real management address after interactive root login.
case $- in
  *i*) if [ "$(id -u)" = 0 ] && [ -x /usr/sbin/murus-info ]; then
         /usr/sbin/murus-info 2>/dev/null || true
       fi ;;
esac
