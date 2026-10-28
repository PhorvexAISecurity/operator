#!/usr/bin/env bash
# Installs and starts the benchmark Telegram bot as a systemd user service on the
# jump host, next to the dashboard (benchmark/deploy/install.sh, run first).
#
#   bash benchmark/bot/deploy/install.sh [RELEASE_DIRECTORY]
#
# RELEASE_DIRECTORY holds benchmark/bot; the default is the dashboard's
# `current`. Giving the bot its own release lets it be installed or upgraded
# without moving `current` or restarting the dashboard. The script never moves
# `current` and never prints a secret. It refuses unless config/bot.env exists
# with mode 600, the dashboard's runtime venv exists, the release holds this bot,
# and the bot's own --check passes for the essentials (Telegram token,
# allowlist, state dir).
set -euo pipefail

BASE=${BENCH_BASE:-$HOME/phorvex-benchmark}
ENV_FILE=$BASE/config/bot.env
UNIT=phorvex-benchmark-bot.service
RELEASE=$(realpath -e -- "${1:-$BASE/current}")
BOT_DIR=$RELEASE/benchmark/bot
fail() { echo "install: $*" >&2; exit 1; }

[[ -f $ENV_FILE ]] || fail "$ENV_FILE is missing; create it from benchmark/bot/deploy/bot.env.example (mode 600)"
[[ $(stat -c %a "$ENV_FILE") == 600 ]] || fail "$ENV_FILE must be mode 600 (chmod 600 $ENV_FILE)"
[[ -x $BASE/runtime/python/bin/python ]] || fail "$BASE/runtime/python is missing; install the dashboard first"
[[ -f $BOT_DIR/service.py ]] || fail "$RELEASE does not contain benchmark/bot"
for key in TELEGRAM_BOT_TOKEN BOT_ALLOWED_USER_IDS; do
  grep -qE "^$key=.+" "$ENV_FILE" || fail "$key is empty in $ENV_FILE"
done
mkdir -p -m 700 "$BASE/bot"
chmod 700 "$BASE/bot"

echo "install: checking the configuration (no secret is printed)"
# Under systemd, with the unit's own EnvironmentFile, so --check parses bot.env
# exactly as the service will (systemd's rules, not the shell's).
systemd-run --user --quiet --pipe --wait --collect \
  -p EnvironmentFile="$ENV_FILE" -p WorkingDirectory="$BOT_DIR" \
  -E BOT_STATE_DIR="$BASE/bot" -E MATHLAB_DATA_DIR="$BASE/data" -E PYTHONDONTWRITEBYTECODE=1 \
  -E PATH="$BASE/runtime/go/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin" \
  "$BASE/runtime/python/bin/python" -B service.py --check \
  || fail "the essential checks failed; fix them and run this again"

install -d -m 700 "$HOME/.config/systemd/user"
# The unit names `current`; point it at the release being installed instead.
sed "s#/home/hami/phorvex-benchmark/current/benchmark/bot#$BOT_DIR#g" "$BOT_DIR/deploy/$UNIT" >"$HOME/.config/systemd/user/$UNIT"
chmod 644 "$HOME/.config/systemd/user/$UNIT"
systemctl --user daemon-reload
systemctl --user enable "$UNIT"
systemctl --user restart "$UNIT"
sleep 2
systemctl --user is-active "$UNIT"
echo "install: running from $BOT_DIR. Logs: journalctl --user -u ${UNIT%.service} -f"
