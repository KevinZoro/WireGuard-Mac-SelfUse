enum PrivilegedScripts {
    // argv contains only fixed scripts, action, interface name, fingerprints and a temporary path.
    static let appleScript = #"""
    on run argv
        set commandText to "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/var/root LC_ALL=C /bin/bash --noprofile --norc -c"
        repeat with arg in argv
            set commandText to commandText & " " & quoted form of (contents of arg)
        end repeat
        try
            return do shell script commandText & " 2>/dev/null" with administrator privileges without altering line endings
        on error number n
            if n = -128 then return "CANCELLED"
            if n = -60006 then return "CANCELLED"
            return "AUTH_FAILED"
        end try
    end run
    """#

    static let bootstrap = #"""
    umask 077
    if [[ $EUID != 0 ]]; then
        printf 'AUTH_FAILED\n'
        exit 0
    fi
    worker=$1
    shift
    runtime=/private/var/run/PersonalWireGuard
    /bin/mkdir -m 700 "$runtime" 2>/dev/null || :
    if [[ -L $runtime || $(/usr/bin/stat -f '%u:%Lp:%HT' "$runtime") != 0:700:Directory ]]; then
        printf 'RUNTIME_FAILED\n'
        exit 0
    fi
    /usr/bin/lockf -ks -t 0 "$runtime/lock" /bin/bash -c "$worker" -- "$runtime" "$@"
    case $? in
        0) ;;
        75) printf 'BUSY\n' ;;
        *) printf 'RUNTIME_FAILED\n' ;;
    esac
    exit 0
    """#

    static let worker = #"""
    set -o pipefail
    umask 077
    runtime=$1 action=$2 name=$3 identity=$4 uid=$5 source=$6 digest=$7
    brew=${8:-/opt/homebrew/bin}
    wireguard=/private/var/run/wireguard
    mapping="$wireguard/$name.name"

    fail() {
        printf '%s\n' "$1"
        exit 0
    }

    [[ $action == status || $action == up || $action == down ]] || fail RUNTIME_FAILED
    [[ $name =~ ^[a-zA-Z0-9_=+.-]{1,15}$ && $identity =~ ^[0-9a-f]{64}$ &&
       $uid =~ ^[1-9][0-9]*$ ]] || fail RUNTIME_FAILED

    # The route monitor started by wg-quick can call wg later. Its PATH must
    # contain only system directories and a root-owned copy of the ARM tool.
    wg="$runtime/wg"
    if [[ -x $brew/wg ]]; then
        /usr/bin/install -CS -m 700 "$brew/wg" "$wg" || fail RUNTIME_FAILED
    fi
    [[ -x $wg ]] || fail MISSING_TOOLS
    export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$runtime"

    hash() {
        /usr/bin/shasum -a 256 | /usr/bin/cut -d ' ' -f 1
    }

    inspect() {
        state=inactive
        real=
        if [[ ! -e $wireguard && ! -L $wireguard ]]; then return; fi
        state=unavailable
        [[ ! -L $wireguard && -d $wireguard ]] || return
        local perms mode map_time socket_time public peers
        perms=$(/usr/bin/stat -f '%u:%Lp' "$wireguard") || return
        [[ $perms =~ ^0:([0-7]{3,4})$ ]] || return
        mode=${BASH_REMATCH[1]}
        (( (8#$mode & 022) == 0 )) || return
        if [[ ! -e $mapping && ! -L $mapping ]]; then state=inactive; return; fi
        [[ ! -L $mapping && -f $mapping &&
           $(/usr/bin/stat -f '%u:%z' "$mapping") =~ ^0:([1-9]|1[0-6])$ ]] || return
        real=$(<"$mapping")
        [[ $real =~ ^utun[0-9]{1,9}$ ]] || return
        if [[ ! -e $wireguard/$real.sock && ! -L $wireguard/$real.sock ]]; then
            state=inactive
            return
        fi
        [[ ! -L $wireguard/$real.sock && -S $wireguard/$real.sock &&
           $(/usr/bin/stat -f '%u' "$wireguard/$real.sock") == 0 ]] || return
        map_time=$(/usr/bin/stat -f '%m' "$mapping") || return
        socket_time=$(/usr/bin/stat -f '%m' "$wireguard/$real.sock") || return
        (( socket_time - map_time > -2 && socket_time - map_time < 2 )) || return
        public=$("$wg" show "$real" public-key) || return
        [[ $public =~ ^[A-Za-z0-9+/]{43}=$ ]] || return
        peers=$("$wg" show "$real" peers | /usr/bin/sort) || return
        if [[ $(printf '%s\n%s' "$public" "$peers" | hash) != "$identity" ]]; then
            state=conflict
            return
        fi
        state=active
    }

    report() {
        local result=$1 handshakes transfers observed=$real
        if [[ $state == active ]]; then
            if handshakes=$("$wg" show "$real" latest-handshakes |
                /usr/bin/awk 'NF != 2 || $2 !~ /^[0-9]+$/ { exit 1 } { print "h " $2 }') &&
                transfers=$("$wg" show "$real" transfer |
                /usr/bin/awk 'NF != 3 || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ { exit 1 }
                              { print "t " $2 " " $3 }'); then
                inspect
                if [[ $state == active && $real == "$observed" ]]; then
                    printf '%s\nactive\n%s\n%s\n' "$result" "$handshakes" "$transfers"
                    exit 0
                fi
            else
                state=unavailable
            fi
        fi
        [[ $state != active ]] || state=unavailable
        printf '%s\n%s\n' "$result" "$state"
        exit 0
    }

    inspect
    if [[ $action == status ]]; then report OK; fi
    if [[ $state == unavailable || $state == conflict ]]; then report STATE_CONFLICT; fi
    if [[ $action == up && $state == active ]]; then report ALREADY_UP; fi
    if [[ $action == down && $state == inactive ]]; then report ALREADY_DOWN; fi

    [[ -x $brew/bash && -r $brew/wg-quick ]] || fail MISSING_TOOLS
    [[ $source == /* && $digest =~ ^[0-9a-f]{64}$ ]] || fail SNAPSHOT_FAILED
    work=$(/usr/bin/mktemp -d "$runtime/op.XXXXXXXX") || fail RUNTIME_FAILED
    trap '/bin/rm -rf -- "$work"' EXIT
    cd "$work" || fail RUNTIME_FAILED
    conf="$work/$name.conf"

    # Read the user-owned snapshot with the GUI user's permissions, then use
    # only the digest-checked copy inside the root-only working directory.
    /usr/bin/sudo -n -u "#$uid" -- /usr/bin/perl -MFcntl=:DEFAULT,:mode -e '
        sysopen(my $fh, $ARGV[0], O_RDONLY | O_NONBLOCK | O_NOFOLLOW) or exit 1;
        my @st = stat($fh);
        exit 1 unless @st && S_ISREG($st[2]) && $st[4] == $< && ($st[2] & 0777) == 0600;
        my $remaining = 131073;
        while ($remaining > 0) {
            my $n = sysread($fh, my $buf, $remaining);
            exit 1 unless defined($n);
            last if $n == 0;
            exit 1 if index($buf, "\0") >= 0;
            print $buf or exit 1;
            $remaining -= $n;
        }
        exit($remaining == 0 ? 1 : 0);
    ' -- "$source" >"$conf" || fail SNAPSHOT_FAILED
    [[ $(hash <"$conf") == "$digest" ]] || fail SNAPSHOT_FAILED
    /usr/bin/awk '
        {
            sub(/#.*/, "")
            equal = index($0, "=")
            if (!equal) next
            key = tolower(substr($0, 1, equal - 1))
            value = tolower(substr($0, equal + 1))
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (key ~ /^(preup|postup|predown|postdown)$/ || (key == "saveconfig" && value != "false")) exit 1
        }
    ' "$conf" || fail UNSAFE_CONFIG

    if [[ $action == up ]]; then
        [[ -x $brew/wireguard-go ]] || fail MISSING_TOOLS
        # Keep the upstream route/DNS monitor running after wg-quick returns.
        /usr/bin/awk '
            { print }
            $0 == "# ~~ function override insertion point ~~" {
                print "detect_launchd() { unset LAUNCHED_BY_LAUNCHD; }"
                seen++
            }
            END { if (seen != 1) exit 1 }
        ' "$brew/wg-quick" >"$work/wg-quick" || fail UNSUPPORTED_TOOLS
        /usr/bin/install -m 700 "$brew/wireguard-go" "$work/wireguard-go" || fail RUNTIME_FAILED
        export WG_QUICK_USERSPACE_IMPLEMENTATION="$work/wireguard-go"
    else
        /bin/cp "$brew/wg-quick" "$work/wg-quick" || fail RUNTIME_FAILED
    fi
    export WG_ENDPOINT_RESOLUTION_RETRIES=2

    result=OK
    # Do not pass raw wg-quick output back to the app. It may contain config lines.
    /usr/bin/arch -arm64 "$brew/bash" --noprofile --norc "$work/wg-quick" "$action" "$conf" \
        </dev/null >/dev/null 2>&1 || result=COMMAND_FAILED
    inspect
    if [[ $action == up && $state != active || $action == down && $state != inactive ]]; then
        result=COMMAND_FAILED
    fi
    report "$result"
    """#
}
