#!/bin/sh
# forester-node installer for Linux (x86_64).
#
#   curl -fsSL https://share.forester.dev/node/install.sh | sudo sh
#
# Downloads the static binary, verifies its checksum, installs it as a systemd service
# running as its own unprivileged user, and prints the pairing code that links the node
# to your share.forester.dev account. Safe to re-run: it upgrades in place and keeps the
# node's identity, data and settings.
set -eu

BASE="${FORESTER_DOWNLOAD_BASE:-https://share.forester.dev/node}"
BIN=/usr/local/bin/forester-node
DATA="${FORESTER_DATA_DIR:-/var/lib/forester-node}"
SERVICE_USER=forester-node

say() { printf '%s\n' "$*"; }
fail() { printf 'forester-node install: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || fail "this installer is for Linux. Other platforms: https://share.forester.dev/#node-guide"
case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64 ;;
  *) fail "no build for $(uname -m) yet. Linux x86_64 and Docker on x86_64 are available now." ;;
esac
[ "$(id -u)" -eq 0 ] || fail "run it with sudo so it can install a system service."
command -v systemctl >/dev/null 2>&1 || fail "systemd was not found. Use the Docker option instead."

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
else
  fail "curl or wget is required."
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

say "Downloading forester-node for Linux $ARCH..."
fetch "$BASE/forester-node-linux-$ARCH" "$TMP/forester-node"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS"
EXPECTED=$(grep " forester-node-linux-$ARCH\$" "$TMP/SHA256SUMS" | cut -d' ' -f1)
ACTUAL=$(sha256sum "$TMP/forester-node" | cut -d' ' -f1)
[ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || fail "checksum mismatch; the download was not installed."

install -m 0755 "$TMP/forester-node" "$BIN"

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
    || adduser --system --home "$DATA" --no-create-home "$SERVICE_USER" >/dev/null
fi
mkdir -p "$DATA"
chown -R "$SERVICE_USER" "$DATA"
chmod 0750 "$DATA"

cat > /etc/systemd/system/forester-node.service <<EOF
[Unit]
Description=Forester storage node
After=network-online.target
Wants=network-online.target

[Service]
User=$SERVICE_USER
ExecStart=$BIN --data-dir $DATA run
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable forester-node >/dev/null 2>&1
systemctl restart forester-node

say "Waiting for the node to connect..."
i=0
while [ $i -lt 30 ]; do
  CODE=$("$BIN" --data-dir "$DATA" pairing-code 2>/dev/null || true)
  case "$CODE" in
    *already*|????????) break ;;
  esac
  i=$((i + 1))
  sleep 1
done

say ""
say "forester-node $("$BIN" --version | cut -d' ' -f2) is installed and running."
case "$CODE" in
  ????????) say "Pairing code: $CODE"
            say "Enter it at https://share.forester.dev (Run a node) to link this node to your account." ;;
  *already*) say "This node is already linked to an account." ;;
  *) say "It is still connecting. Show the code later with: sudo forester-node --data-dir $DATA pairing-code" ;;
esac
say "Settings: $DATA/config.toml    Logs: journalctl -u forester-node -f"
