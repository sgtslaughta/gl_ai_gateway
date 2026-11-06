#!/bin/sh
# Run inside the built image: docker run --rm -v "$PWD/tests:/t:ro" IMAGE sh /t/smoke.sh
fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

[ "$(id -u)" != 0 ] || bad "running as root"

for t in bash curl jq git python3 ai-token ai-review; do
    command -v "$t" >/dev/null 2>&1 || bad "missing tool: $t"
done

for t in apt apt-get dnf apk pip pip3 gcc cc ssh scp nc wget sudo docker kubectl; do
    ! command -v "$t" >/dev/null 2>&1 || bad "forbidden tool present: $t"
done

sid=$(find / -xdev -perm /6000 -type f 2>/dev/null)
[ -z "$sid" ] || bad "setuid/setgid files: $sid"

keys=$(find /etc /home \( -iname 'id_rsa*' -o -iname 'id_ed25519*' -o -iname '*.key' \
    -o -iname '*token*' -o -iname '*secret*' -o -iname '*.p12' -o -iname '*.pfx' \
    -o -iname '.netrc' -o -iname '*credentials*' \) 2>/dev/null)
[ -z "$keys" ] || bad "key or token files: $keys"

[ "$fail" = 0 ] && echo "smoke: ok"
exit "$fail"
