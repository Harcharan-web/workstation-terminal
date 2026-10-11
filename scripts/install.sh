#!/bin/sh
# Install sshweb for the current (non-root) user.
#
#   scripts/install.sh [path/to/sshweb]
#
# - copies the binary to ~/.local/bin/sshweb (override with PREFIX=/some/dir)
# - creates ~/.sshweb with a sample config and empty key files (if missing)
# - optionally installs a launchd user agent (INSTALL_LAUNCHD=1)
set -eu

if [ "$(id -u)" = "0" ]; then
  echo "Do not run this as root; sshweb runs as an ordinary user." >&2
  exit 1
fi

SRC="${1:-target/release/sshweb}"
PREFIX="${PREFIX:-$HOME/.local/bin}"
if [ ! -x "$SRC" ]; then
  echo "binary $SRC not found; build it first with: cargo build --release" >&2
  exit 1
fi

mkdir -p "$PREFIX"
install -m 0755 "$SRC" "$PREFIX/sshweb"
echo "installed $PREFIX/sshweb"

if [ ! -f "$HOME/.sshweb/config.yaml" ]; then
  "$PREFIX/sshweb" config init
else
  echo "keeping existing $HOME/.sshweb/config.yaml"
fi

if [ "${INSTALL_LAUNCHD:-0}" = "1" ]; then
  AGENT="$HOME/Library/LaunchAgents/com.sshweb.gateway.plist"
  mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
  sed -e "s|@BIN@|$PREFIX/sshweb|g" -e "s|@HOME@|$HOME|g" \
    "$(dirname "$0")/../packaging/com.sshweb.gateway.plist" > "$AGENT"
  chmod 0644 "$AGENT"
  launchctl bootout "gui/$(id -u)" "$AGENT" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$AGENT"
  echo "launchd agent installed: $AGENT (logs: ~/Library/Logs/sshweb.log)"
fi

case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) echo "note: add $PREFIX to your PATH" ;;
esac
cat <<MSG

Next steps:
  sshweb keys add --user "$(id -un | tr 'A-Z' 'a-z')" --access local ~/.ssh/id_ed25519.pub
  sshweb config validate
  sshweb serve            # then open http://127.0.0.1:7681/
MSG
