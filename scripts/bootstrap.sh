#!/usr/bin/env bash
# Re-executes itself as root (via sudo) and runs lagsw with preset args. Linux counterpart of bootstrap.ps1.
set -euo pipefail

# ---- Preconfigured settings: edit these ----
EXE_NAME="lagsw"
APP_ARGS=(
    --config profiles/div1.sw.yml
    --log-level info
    --resolve-region
    # --server name-or-address
)
# --------------------------------------------

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# In the repo the script lives in scripts/; in a package it sits next to the executable.
if [[ "$(basename "$here")" == "scripts" ]]; then root="$(dirname "$here")"; else root="$here"; fi

# Packet capture and keyboard polling (/dev/input) need root.
if [[ $EUID -ne 0 ]]; then
    exec sudo -E "$0" "$@"
fi

# Relative config paths resolve against the first of these that contains the config.
config=""
for ((i = 0; i < ${#APP_ARGS[@]}; i++)); do
    if [[ "${APP_ARGS[$i]}" == "--config" ]]; then config="${APP_ARGS[$((i + 1))]}"; fi
done
work_dir="$root"
for dir in "$here" "$root/profiles" "$root"; do
    if [[ -n "$config" && -e "$dir/$config" ]]; then work_dir="$dir"; break; fi
done
cd "$work_dir"

candidates=(
    "$here/$EXE_NAME"
    "$root/build/linux/x86_64/release/$EXE_NAME"
    "$root/build/linux/x86_64/debug/$EXE_NAME"
    "$root/build/linux/arm64/release/$EXE_NAME"
    "$root/build/linux/arm64/debug/$EXE_NAME"
)
exe=""
for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then exe="$candidate"; break; fi
done
if [[ -z "$exe" ]]; then
    echo "Could not find $EXE_NAME. Looked in:" >&2
    printf '  %s\n' "${candidates[@]}" >&2
    exit 1
fi

echo "> $exe ${APP_ARGS[*]} $*"
set +e
"$exe" "${APP_ARGS[@]}" "$@"
code=$?
echo
echo "lagsw exited with code $code"
exit $code
