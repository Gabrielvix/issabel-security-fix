#!/usr/bin/env bash
exec >>/var/log/issabel-security-fix-postreboot.log 2>&1
echo "=== post-reboot $(date -Iseconds) ==="
/opt/issabel-security-fix/issabel-security-fix.sh --verify
echo EXIT:$?
/opt/issabel-security-fix/issabel-security-fix.sh --scan 2>/dev/null | grep -E 'RESULTADO|CRITICAL|OK '
