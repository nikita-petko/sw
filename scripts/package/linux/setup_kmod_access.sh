#!/usr/bin/env bash
# Lets lagsw's kernel-module backend run without root: installs the udev rule that opens /dev/swdivert to a group (70-swdivert.rules, next to
# this script), creates the group, adds users to it and optionally gives the lagsw executable the capabilities it needs.
#
# usage: setup_kmod_access.sh install [--group lagsw] [--user NAME]... [--lagsw PATH] [--dry-run]
#        setup_kmod_access.sh remove  [--group lagsw] [--dry-run]
#        setup_kmod_access.sh status  [--group lagsw] [--lagsw PATH]
#
#   --group NAME   the group the device is opened to (default lagsw; the rule file names it and is rewritten to the one given here)
#   --user NAME    add this user to the group (repeatable; the user that ran sudo is added when none is given). A running session
#                  has to log in again before it has the group
#   --lagsw PATH   also run `setcap cap_net_admin,cap_sys_module+ep PATH`: the executable then needs neither root nor sudo. The kernel module
#                  it carries is loaded by lagsw itself (CAP_SYS_MODULE); the device is opened through the group
#   --dry-run      print what would be done
#
# Environment: LAGSW_UDEV_RULES_DIR (default /etc/udev/rules.d).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULE_NAME="70-swdivert.rules"
RULES_DIR="${LAGSW_UDEV_RULES_DIR:-/etc/udev/rules.d}"

die() { echo "error: $*" >&2; exit 1; }

action="${1:-}"
[[ -n "$action" ]] || die "usage: $0 install|remove|status [options] (see the top of this file)"
shift
group="lagsw"; users=(); lagsw=""; dry_run=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --group) group="${2:?--group needs a name}"; shift 2 ;;
        --user) users+=("${2:?--user needs a name}"); shift 2 ;;
        --lagsw) lagsw="${2:?--lagsw needs a path}"; shift 2 ;;
        --dry-run) dry_run=1; shift ;;
        *) die "unknown option $1" ;;
    esac
done
[[ "$group" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "'$group' is not a valid group name"

run() {
    if [[ $dry_run -eq 1 ]]; then echo "+ $*"; else "$@"; fi
}

# The rule file as installed: the one shipped here, with the group substituted
rule_text() {
    local source="$here/$RULE_NAME"
    [[ -f "$source" ]] || die "$source is missing"
    sed "s/GROUP=\"lagsw\"/GROUP=\"$group\"/" "$source"
}

case "$action" in
    install)
        if [[ $dry_run -eq 0 && $EUID -ne 0 ]]; then
            args=(install --group "$group")
            for user in ${users[@]+"${users[@]}"}; do args+=(--user "$user"); done
            [[ -n "$lagsw" ]] && args+=(--lagsw "$lagsw")
            # The user that asks for it is the one to give access to, once root has dropped the knowledge of who that was
            [[ ${#users[@]} -eq 0 ]] && args+=(--user "$(id -un)")
            exec sudo -E "$0" "${args[@]}"
        fi
        [[ ${#users[@]} -gt 0 ]] || { [[ -n "${SUDO_USER:-}" ]] && users=("$SUDO_USER"); } || true

        for user in ${users[@]+"${users[@]}"}; do
            id -u "$user" > /dev/null 2>&1 || die "no such user: $user"
        done
        if ! getent group "$group" > /dev/null; then
            run groupadd --system "$group"
        fi
        for user in ${users[@]+"${users[@]}"}; do
            run usermod --append --groups "$group" "$user"
        done

        if [[ $dry_run -eq 1 ]]; then
            echo "+ write $RULES_DIR/$RULE_NAME:"
            rule_text | sed 's/^/    /'
        else
            mkdir -p "$RULES_DIR"
            rule_text > "$RULES_DIR/$RULE_NAME"
            chmod 644 "$RULES_DIR/$RULE_NAME"
        fi
        if command -v udevadm > /dev/null; then
            run udevadm control --reload-rules
            # A module that is loaded already has its node: have udev apply the rule to it now
            if [[ -e /dev/swdivert || $dry_run -eq 1 ]]; then
                run udevadm trigger --action=change --subsystem-match=misc --sysname-match=swdivert
                run udevadm settle
            fi
        else
            echo "note: udevadm was not found; the rule applies at the next boot or when the device is created" >&2
        fi
        if [[ -n "$lagsw" ]]; then
            [[ $dry_run -eq 1 || -x "$lagsw" ]] || die "$lagsw is not an executable"
            command -v setcap > /dev/null || [[ $dry_run -eq 1 ]] || die "setcap was not found (libcap)"
            run setcap cap_net_admin,cap_sys_module+ep "$lagsw"
        fi
        echo "done: /dev/swdivert is opened to the group '$group'."
        [[ ${#users[@]} -gt 0 ]] && echo "Users added: ${users[*]} (they have to log in again before the group applies)."
        ;;

    remove)
        if [[ $dry_run -eq 0 && $EUID -ne 0 ]]; then exec sudo -E "$0" remove --group "$group"; fi
        run rm -f "$RULES_DIR/$RULE_NAME"
        command -v udevadm > /dev/null && run udevadm control --reload-rules
        echo "done: the rule is removed. The group '$group' and its members are left as they are (groupdel $group to drop it)."
        ;;

    status)
        if [[ -f "$RULES_DIR/$RULE_NAME" ]]; then echo "rule:   installed ($RULES_DIR/$RULE_NAME)"; else echo "rule:   not installed"; fi
        if getent group "$group" > /dev/null; then echo "group:  $group, members: $(getent group "$group" | cut -d: -f4)"; else echo "group:  $group does not exist"; fi
        if [[ -e /dev/swdivert ]]; then echo "device: $(stat -c '%A %U:%G' /dev/swdivert)"; else echo "device: /dev/swdivert does not exist (the module is not loaded)"; fi
        if [[ -n "$lagsw" ]]; then
            if command -v getcap > /dev/null; then echo "caps:   $(getcap "$lagsw" 2>/dev/null || true)"; fi
        fi
        ;;

    *) die "unknown action '$action' (install, remove or status)" ;;
esac
