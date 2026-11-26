enum SessionScripts {
    static let bootstrap = #"""
    umask 077
    [[ $EUID == 0 ]] || { printf 'AUTH_FAILED\n'; exit 0; }
    runtime=/private/var/run/PersonalWireGuard
    /bin/mkdir -m 700 "$runtime" 2>/dev/null || :
    if [[ -L $runtime || $(/usr/bin/stat -f '%u:%Lp:%HT' "$runtime") != 0:700:Directory ]]; then
        printf 'RUNTIME_FAILED\n'
        exit 0
    fi
    session=$1
    shift
    /usr/bin/perl -e "$session" -- "$runtime" "$@" || printf 'SESSION_FAILED\n'
    """#

    private static let transport = #"""
    use strict;
    use warnings;
    use Socket qw(AF_UNIX SOCK_STREAM pack_sockaddr_un);
    use File::Temp qw(tempdir);
    use Digest::SHA qw(sha256_hex);
    use MIME::Base64 qw(decode_base64);
    use Fcntl qw(F_GETFD F_SETFD FD_CLOEXEC);

    my ($runtime, $worker, $path, $pid, $uid, @manifest) = @ARGV;
    exit 1 unless $< == 0 && $> == 0 && $pid =~ /^[1-9][0-9]*$/ && $uid =~ /^[1-9][0-9]*$/;
    exit 1 unless $path =~ m{^/private/tmp/wgc\.[A-Za-z0-9]+/socket$};
    socket(my $socket, AF_UNIX, SOCK_STREAM, 0) or exit 1;
    fcntl($socket, F_SETFD, FD_CLOEXEC) or exit 1;
    connect($socket, pack_sockaddr_un($path)) or exit 1;
    # Darwin sys/un.h: SOL_LOCAL = 0, LOCAL_PEERPID = 2.
    my $peer = getsockopt($socket, 0, 2);
    exit 1 unless defined($peer) && unpack('i', $peer) == $pid;

    $SIG{PIPE} = 'IGNORE';
    $SIG{ALRM} = sub { exit 0 };
    my $toolkit = tempdir('authorization.XXXXXXXX', DIR => $runtime, CLEANUP => 1);

    sub read_bytes {
        my ($size) = @_;
        my $bytes = '';
        while (length($bytes) < $size) {
            my $n = sysread($socket, $bytes, $size - length($bytes), length($bytes));
            return unless defined($n) && $n > 0;
        }
        return $bytes;
    }

    sub read_frame {
        my ($limit) = @_;
        my $header = read_bytes(4);
        return unless defined $header;
        my $size = unpack('N', $header);
        return if $size > $limit;
        return read_bytes($size);
    }

    sub send_frame {
        my ($body) = @_;
        my $bytes = pack('N', length($body)) . $body;
        my $offset = 0;
        while ($offset < length($bytes)) {
            my $n = syswrite($socket, $bytes, length($bytes) - $offset, $offset);
            return unless defined($n) && $n > 0;
            $offset += $n;
        }
        return 1;
    }

    sub receive_file {
        my ($name, $digest, $max_size, $mode) = @_;
        my $body = read_frame($max_size);
        exit 1 unless defined($body) && sha256_hex($body) eq $digest;
        open(my $out, '>:raw', "$toolkit/$name") or exit 1;
        print {$out} $body or exit 1;
        close($out) or exit 1;
        chmod $mode, "$toolkit/$name" or exit 1;
    }
    """#

    static let server = transport + "\n" + #"""
    # File names and content digests are fixed by the command that was approved.
    alarm 30;
    my %copied;
    exit 1 unless @manifest >= 4 && @manifest <= 32;
    for my $item (@manifest) {
        exit 1 unless $item =~ /\A([a-zA-Z0-9_+-][a-zA-Z0-9._+-]{0,79}):([0-9a-f]{64})\z/;
        my ($name, $digest) = ($1, $2);
        exit 1 if $copied{$name}++;
        receive_file($name, $digest, 32 * 1024 * 1024, 0700);
    }
    for my $name ('bash', 'wg', 'wg-quick', 'wireguard-go') {
        exit 1 unless $copied{$name};
    }
    send_frame('READY') or exit 0;

    alarm 0;
    while (1) {
        my $request = read_frame(8192);
        alarm 0;
        exit 0 unless defined($request);
        my ($action, $name, $identity, $path64, $digest, @extra) = split(/\t/, $request, -1);
        exit 1 if @extra || !defined($digest)
            || $action !~ /\A(?:observe|status|up|down)\z/
            || $name !~ /\A[a-zA-Z0-9_=+.-]{1,15}\z/
            || $identity !~ /\A[0-9a-f]{64}\z/;
        my $observing = $action eq 'observe';
        $action = 'status' if $observing;
        my $source = decode_base64($path64);
        exit 1 if $source =~ /\0/;
        if ($action eq 'status') {
            exit 1 if length($source) || length($digest);
        } else {
            exit 1 unless $source =~ m{^/} && $digest =~ /\A[0-9a-f]{64}\z/;
        }

        my $reply = '';
        if (open(my $output, '-|', '/usr/bin/lockf', '-ks', '-t', '0', "$runtime/lock",
            '/bin/bash', '-c', $worker, '--', $runtime, $action, $name, $identity,
            $uid, $source, $digest, $toolkit)) {
            while (read($output, my $chunk, 8192)) {
                $reply .= $chunk;
                exit 1 if length($reply) > 2_000_000;
            }
            if (!close($output)) {
                $reply = ($? >> 8) == 75 ? 'BUSY' : 'RUNTIME_FAILED';
            }
        } else {
            $reply = 'RUNTIME_FAILED';
        }
        send_frame($reply) or exit 0;
    }
    """#

    static let appSplitServer = transport + "\n" + #"""
    use Fcntl qw(LOCK_EX LOCK_NB);
    use IO::Handle;
    use IO::Select;
    use JSON::PP qw(decode_json);
    use POSIX qw(WNOHANG _exit);

    sub close_dns {
        my ($pipe) = @_;
        return unless defined($pipe);
        print {$pipe} "quit\n";
        close($pipe);
    }

    sub install_dns {
        my $id = qx{/usr/bin/uuidgen};
        chomp($id);
        return unless !$? && $id =~ /\A[A-Fa-f0-9-]{36}\z/;
        open(my $pipe, '|-', '/usr/sbin/scutil') or return;
        if (fcntl($pipe, F_SETFD, FD_CLOEXEC)) {
            $pipe->autoflush(1);
            # The dynamic store removes this resolver when scutil exits.
            if (print {$pipe} "d.init\nd.add ServerAddresses * 172.19.255.2\n",
                "d.add SupplementalMatchDomains * \"\"\n",
                "d.add SupplementalMatchOrders * # 1\n",
                "add State:/Network/Service/$id/DNS temporary\n") {
                for (1..20) {
                    my $dns = qx{/usr/sbin/scutil --dns};
                    next if $?;
                    my ($primary) = $dns =~ /^resolver #1\n((?:[ \t]+[^\n]*\n)+)/m;
                    return $pipe if defined($primary) && $primary =~ /^[ \t]+nameserver\[0\][ \t]*:[ \t]*172\.19\.255\.2$/m;
                    select(undef, undef, undef, 0.1);
                }
            }
        }
        close_dns($pipe);
        return;
    }

    alarm 30;
    exit 1 unless @manifest == 2;
    my ($binary_hash) = $manifest[0] =~ /\Asing-box:([0-9a-f]{64})\z/;
    my ($config_hash) = $manifest[1] =~ /\Aapp-split\.json:([0-9a-f]{64})\z/;
    exit 1 unless defined($binary_hash) && defined($config_hash);
    receive_file('sing-box', $binary_hash, 128 * 1024 * 1024, 0700);
    receive_file('app-split.json', $config_hash, 1024 * 1024, 0600);
    alarm 0;

    open(my $config_file, '<:raw', "$toolkit/app-split.json") or exit 1;
    my $config = eval { local $/; decode_json(<$config_file>) };
    close($config_file);
    exit 1 unless ref($config) eq 'HASH' && ref($config->{outbounds}) eq 'ARRAY';
    my $reality = grep { $_->{type} eq 'vless' && $_->{tag} eq 'vpn' } @{$config->{outbounds}};

    open(my $lock, '>>', "$runtime/lock") or exit 1;
    fcntl($lock, F_SETFD, FD_CLOEXEC) or exit 1;
    if (!flock($lock, LOCK_EX | LOCK_NB)) {
        send_frame('BUSY');
        exit 0;
    }
    my $routes = qx{/usr/sbin/netstat -rn -f inet};
    if ($? || $routes =~ /^\S+\s+(?:\S+\s+){2}utun\d+\b/m
        || glob('/private/var/run/wireguard/utun*.sock')) {
        send_frame('VPN_ACTIVE');
        exit 0;
    }
    my $interfaces = qx{/sbin/ifconfig -a};
    if ($? || $interfaces =~ /\binet 172\.19\.255\.1\b/) {
        send_frame('TUN_ADDRESS_IN_USE');
        exit 0;
    }

    my $stopping = 0;
    $SIG{TERM} = $SIG{INT} = $SIG{HUP} = sub { $stopping = 1 };
    my $service = fork();
    if (!defined($service)) {
        send_frame('TUN_START_FAILED');
        exit 0;
    }
    if (!$service) {
        open(STDIN, '<', '/dev/null') or _exit(126);
        open(STDOUT, '>', '/dev/null') or _exit(126);
        open(STDERR, '>', '/dev/null') or _exit(126);
        exec { "$toolkit/sing-box" } "$toolkit/sing-box", 'run', '-c', "$toolkit/app-split.json"
            or _exit(127);
    }

    my $control = IO::Select->new($socket);
    my $ready = 0;
    my $dns;
    my $failure = 'TUN_START_FAILED';
    for (1..80) {
        if (waitpid($service, WNOHANG) == $service) {
            send_frame('TUN_START_FAILED');
            exit 0;
        }
        last if $stopping || $control->can_read(0.1);
        my $interfaces = qx{/sbin/ifconfig -a};
        next unless $interfaces =~ /^(utun\d+):[^\n]*(?:\n[ \t][^\n]*)*\n[ \t]+inet 172\.19\.255\.1\b/m;
        my $tun = $1;
        my $route = qx{/sbin/route -n get 1.1.1.1};
        next unless $route =~ /^\s*interface:\s+\Q$tun\E\s*$/m;
        if ($reality) {
            $dns = install_dns();
            if (!defined($dns)) {
                $failure = 'TUN_DNS_FAILED';
                last;
            }
        }
        $ready = send_frame('READY');
        last;
    }
    unlink "$toolkit/app-split.json";
    if ($ready) {
        while (!$stopping && !$control->can_read(0.25)) {
            if (waitpid($service, WNOHANG) == $service) {
                close_dns($dns);
                exit 0;
            }
        }
    }
    close_dns($dns);
    kill 'TERM', $service;
    for (1..40) {
        if (waitpid($service, WNOHANG) == $service) {
            send_frame($failure) unless $ready;
            exit 0;
        }
        select(undef, undef, undef, 0.1);
    }
    kill 'KILL', $service;
    waitpid($service, 0);
    send_frame($failure) unless $ready;
    """#
}
