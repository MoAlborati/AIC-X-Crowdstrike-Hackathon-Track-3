# shellcheck shell=bash
# scripts/lib/portable.sh — small shims so the repo's scripts run unchanged on Linux/WSL (GNU userland,
# bash 5) and on macOS (BSD userland, stock /bin/bash 3.2). Source it; it defines functions only.
#
#   run_with_timeout SECS CMD...  GNU `timeout --kill-after=10` semantics: SIGTERM at SECS, SIGKILL 10s
#                                 later, exit 124 on timeout. Uses `timeout`, else Homebrew's `gtimeout`,
#                                 else a perl fallback (perl ships with macOS), else a pure-bash fallback
#                                 (background job + kill). PORTABLE_TIMEOUT_IMPL=perl|bash forces a
#                                 fallback (used to test them on Linux).
#   sha256_file FILE              prints the hex digest (sha256sum, else `shasum -a 256`).
#   host_os                       prints linux | macos | wsl | other.
#
# bash 3.2 notes for anyone editing scripts here: no `mapfile`/`readarray`, no associative arrays, no
# ${v,,}; and under `set -u` an EMPTY array expanded as "${a[@]}" is an "unbound variable" error, so
# write ${a[@]+"${a[@]}"} wherever the array can be empty.

run_with_timeout() { # secs cmd...
  local secs="$1"; shift
  local impl="${PORTABLE_TIMEOUT_IMPL:-auto}"
  if [ "$impl" = auto ] && command -v timeout >/dev/null 2>&1; then timeout --kill-after=10 "$secs" "$@"; return $?; fi
  if [ "$impl" = auto ] && command -v gtimeout >/dev/null 2>&1; then gtimeout --kill-after=10 "$secs" "$@"; return $?; fi
  if [ "$impl" = bash ] || ! command -v perl >/dev/null 2>&1; then _bash_timeout "$secs" "$@"; return $?; fi
  # The child runs in its own process group so the whole tree (node --test spawns workers) is signalled.
  perl -e '
    use POSIX ":sys_wait_h";
    my ($secs, @cmd) = @ARGV; my $timed_out = 0;
    my $pid = fork(); die "fork: $!" unless defined $pid;
    if ($pid == 0) { setpgrp(0, 0); exec { $cmd[0] } @cmd or do { print STDERR "exec $cmd[0]: $!\n"; POSIX::_exit(127) } }
    $SIG{ALRM} = sub {
      if (!$timed_out) { $timed_out = 1; kill "TERM", -$pid; alarm 10 } else { kill "KILL", -$pid }
    };
    alarm $secs;
    my $r;
    do { $r = waitpid($pid, 0) } while ($r == -1 && $!{EINTR});
    my $st = $?; alarm 0;
    exit 124 if $timed_out;
    exit(($st & 127) ? 128 + ($st & 127) : ($st >> 8));
  ' "$secs" "$@"
}

# Pure-bash fallback: background job + watcher. Signals the job and its direct children (pkill -P), which
# covers node --test and its per-file workers.
_bash_timeout() { # secs cmd...
  local secs="$1"; shift
  local mark pid w rc
  mark="$(mktemp "${TMPDIR:-/tmp}/run_with_timeout.XXXXXX")" || return 125
  rm -f "$mark"
  "$@" &
  pid=$!
  ( sleep "$secs"
    if kill -0 "$pid" 2>/dev/null; then
      : > "$mark"; pkill -TERM -P "$pid" 2>/dev/null; kill -TERM "$pid" 2>/dev/null
      sleep 10; pkill -KILL -P "$pid" 2>/dev/null; kill -KILL "$pid" 2>/dev/null
    fi ) &
  w=$!
  wait "$pid"; rc=$?
  pkill -P "$w" 2>/dev/null; kill "$w" 2>/dev/null; wait "$w" 2>/dev/null
  if [ -e "$mark" ]; then rm -f "$mark"; rc=124; fi
  return "$rc"
}

sha256_file() { # file
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -c1-64
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -c1-64
  else echo "sha256_file: need sha256sum or shasum" >&2; return 127; fi
}

host_os() {
  case "$(uname -s 2>/dev/null)" in
    Darwin) echo macos ;;
    Linux) if grep -qi microsoft /proc/version 2>/dev/null; then echo wsl; else echo linux; fi ;;
    *) echo other ;;
  esac
}
