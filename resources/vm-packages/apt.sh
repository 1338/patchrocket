#!/bin/sh
set -eu

operation=$1
package=$2
expected_machine=$3
expected_arch=$4
previous=$5
approved=$6

fail() {
    printf '%s\n' "$1"
    exit 1
}

case "$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')" in
    ubuntu|debian) ;;
    *) fail unsupported_os ;;
esac
machine=$(sha256sum < /etc/machine-id)
machine=${machine%% *}
[ -s /etc/machine-id ] || fail missing_identity

read_installed() {
    installed=$(dpkg-query -W -f='${Package}|${Architecture}|${Version}|${Status}\n' -- "$1" 2>/dev/null) || fail not_installed
    case "$installed" in
        *'
'*) fail ambiguous_package ;;
    esac
    IFS='|' read -r name arch version status <<DATA
$installed
DATA
    case "$status" in
        'install ok installed'|'hold ok installed') ;;
        *) fail not_installed ;;
    esac
}

read_installed "$package"
target=$name
[ "$arch" = all ] || target=$name:$arch

if [ "$operation" != plan ]; then
    [ "$machine" = "$expected_machine" ] && [ "$arch" = "$expected_arch" ] || fail identity_changed
fi
if [ "$operation" = observe ]; then
    printf '%s\t%s\t%s\t%s\n' "$machine" "$name" "$arch" "$version"
    exit 0
fi

# Serialize PatchRocket runs even if the host was registered through multiple SSH aliases.
if [ "$operation" = apply ]; then
    exec 9>>/run/patchrocket-apt.lock
    flock -n 9 || fail busy
    read_installed "$target"
    [ "$arch" = "$expected_arch" ] && [ "$version" = "$previous" ] || fail version_changed
fi
[ "$status" = 'install ok installed' ] || fail held_package
audit=$(dpkg --audit) || fail unhealthy_packages
[ -z "$audit" ] || fail unhealthy_packages

candidate=$(apt-cache policy "$target" | awk '$1 == "Candidate:" { print $2 }')
case "$candidate" in
    [0-9]*) ;;
    *) fail no_upgrade ;;
esac
dpkg --compare-versions "$candidate" gt "$version" || fail no_upgrade
if [ "$operation" = apply ] && [ "$candidate" != "$approved" ]; then
    fail version_changed
fi

apt_install() {
    apt-get --assume-yes --only-upgrade --no-remove --no-install-recommends \
        -o APT::Get::AllowUnauthenticated=false \
        -o Acquire::AllowInsecureRepositories=false \
        -o APT::Get::allow-downgrades=false \
        -o APT::Get::allow-change-held-packages=false \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
        -o DPkg::Lock::Timeout=0 "$@" install -- "$target=$candidate"
}

simulation=$(apt_install --simulate 2>/dev/null) || fail simulation_failed
# Refuse steps for other packages, including changes to another architecture.
printf '%s\n' "$simulation" | awk -v name="$name" -v target="$target" -v arch="$arch" '
    $1 == "Inst" || $1 == "Conf" {
        if ($2 != name && $2 != target) exit 1
        if ($NF != "[" arch "])") exit 1
        if ($1 == "Inst") installed++
        if ($1 == "Conf") configured++
    }
    $1 == "Remv" || $1 == "Purg" { exit 1 }
    END { if (installed != 1 || configured != 1) exit 1 }
' || fail additional_changes

if [ "$operation" = plan ]; then
    printf '%s\t%s\t%s\t%s\t%s\n' "$machine" "$name" "$arch" "$version" "$candidate"
    exit 0
fi

scratch=$(mktemp -d /tmp/patchrocket-apt.XXXXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
export PATCHROCKET_PACKAGE="$name" PATCHROCKET_ARCH="$arch" PATCHROCKET_TARGET="$target"
export PATCHROCKET_PREVIOUS="$previous" PATCHROCKET_CANDIDATE="$candidate"
# APT invokes this before dpkg, while holding the package manager lock.
# Check the actual archive as well as the installed version to close the simulation race.
cat > "$scratch/check" <<'HOOK'
set -eu
IFS= read -r archive
if IFS= read -r extra; then exit 1; fi
[ "$(dpkg-deb -f "$archive" Package)" = "$PATCHROCKET_PACKAGE" ]
[ "$(dpkg-deb -f "$archive" Architecture)" = "$PATCHROCKET_ARCH" ]
[ "$(dpkg-deb -f "$archive" Version)" = "$PATCHROCKET_CANDIDATE" ]
installed=$(dpkg-query -W -f='${Version}|${Status}' -- "$PATCHROCKET_TARGET")
[ "$installed" = "$PATCHROCKET_PREVIOUS|install ok installed" ]
HOOK
apt_install -o "DPkg::Pre-Install-Pkgs::=/bin/sh $scratch/check" 9>&- >/dev/null 2>&1 || fail install_failed
