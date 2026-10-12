#!/usr/bin/env bash
# make-submission-snapshot.sh — build the single-commit public snapshot of main (issue #73).
#
# Usage: scripts/make-submission-snapshot.sh [--skip-tests] [--no-fetch] [--force]
#
#   1. fails unless the working tree is clean and HEAD == origin/main (after `git fetch origin`);
#   2. runs `scripts/eval.sh test` (skip with --skip-tests);
#   3. writes ONE parentless commit whose tree is exactly HEAD's tree;
#   4. scans that tree (minus anything gitignored) for secrets (gitleaks if installed, else regex),
#      local home/scratch paths, and internal tooling words. Known-inert strings are listed in
#      scripts/submission-scan-allowlist.tsv. Any other hit fails the run and NO ref is created;
#   5. on a clean scan, creates branch `submission-snapshot` and tag `v1.0-submission` locally;
#   6. prints the commands a repo owner runs to publish it. This script never pushes.
#
# --force replaces an existing local `submission-snapshot` branch / `v1.0-submission` tag.
# Env: SNAPSHOT_BRANCH, SNAPSHOT_TAG, SNAPSHOT_REMOTE (default origin), SNAPSHOT_REPO_NAME,
#      SNAPSHOT_NO_GITLEAKS=1 (use the built-in regex set even when gitleaks is installed).
# bash 3.2 safe (macOS stock bash): no mapfile, no associative arrays, no ${v,,}.
set -euo pipefail

BRANCH="${SNAPSHOT_BRANCH:-submission-snapshot}"
TAG="${SNAPSHOT_TAG:-v1.0-submission}"
REMOTE="${SNAPSHOT_REMOTE:-origin}"
REPO_NAME="${SNAPSHOT_REPO_NAME:-AIC-X-Crowdstrike-Hackathon-Track-3-submission}"
SKIP_TESTS=0; FETCH=1; FORCE=0
for a in "$@"; do
  case "$a" in
    --skip-tests) SKIP_TESTS=1 ;;
    --no-fetch) FETCH=0 ;;
    --force) FORCE=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

die() { printf 'SNAPSHOT FAIL: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s ==\n' "$*"; }

REPO="$(git rev-parse --show-toplevel 2>/dev/null)" || die "not inside a git repository"
cd "$REPO"
ALLOWLIST="scripts/submission-scan-allowlist.tsv"

# --- 1. clean tree, HEAD == origin/main ------------------------------------------------------------
step "1/6 verify clean tree and HEAD == $REMOTE/main"
if [ "$FETCH" = 1 ]; then git fetch -q "$REMOTE" main || die "git fetch $REMOTE main failed"; fi
DIRTY="$(git status --porcelain --untracked-files=normal)"
[ -z "$DIRTY" ] || { printf '%s\n' "$DIRTY" >&2; die "working tree is not clean (commit, stash or remove the files above)"; }
HEAD_SHA="$(git rev-parse HEAD)"
MAIN_SHA="$(git rev-parse --verify -q "$REMOTE/main^{commit}")" || die "no $REMOTE/main ref"
[ "$HEAD_SHA" = "$MAIN_SHA" ] || die "HEAD ($HEAD_SHA) != $REMOTE/main ($MAIN_SHA); check out $REMOTE/main first"
SHORT="$(git rev-parse --short=12 HEAD)"
TREE="$(git rev-parse 'HEAD^{tree}')"
echo "  ok  HEAD = $REMOTE/main = $HEAD_SHA (tree $TREE)"

if [ "$FORCE" = 0 ]; then
  git rev-parse -q --verify "refs/heads/$BRANCH" >/dev/null && die "branch $BRANCH exists (delete it or pass --force)"
  git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "tag $TAG exists (delete it or pass --force)"
fi

# --- 2. tests --------------------------------------------------------------------------------------
step "2/6 scripts/eval.sh test"
if [ "$SKIP_TESTS" = 1 ]; then
  echo "  SKIPPED (--skip-tests)"
else
  scripts/eval.sh test || die "scripts/eval.sh test failed"
fi

# --- 3. orphan commit of the exact tree --------------------------------------------------------------
step "3/6 orphan commit of tree $TREE"
MSG="SentinelProxy — CrowdStrike Track 3 submission (squashed snapshot of main @ $SHORT)

Single-commit snapshot of $REMOTE/main $HEAD_SHA, built by scripts/make-submission-snapshot.sh.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
SNAP="$(printf '%s\n' "$MSG" | git commit-tree "$TREE")" || die "git commit-tree failed"
[ "$(git rev-list --parents -n1 "$SNAP")" = "$SNAP" ] || die "snapshot commit has parents"
[ "$(git rev-parse "$SNAP^{tree}")" = "$TREE" ] || die "snapshot tree differs from HEAD tree"
echo "  ok  commit $SNAP (no parents, tree identical)"

# --- 4. scan -----------------------------------------------------------------------------------------
step "4/6 scan snapshot tree (secrets, local paths, internal words)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/snapscan.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
SRC="$WORK/tree"; mkdir "$SRC"
git archive "$SNAP" | tar -x -C "$SRC"
# Drop anything gitignored (tracked-but-ignored files included) from the scan.
git -c core.quotePath=false ls-tree -r --name-only "$SNAP" > "$WORK/all"
git -c core.quotePath=false check-ignore --no-index --stdin < "$WORK/all" > "$WORK/ignored" || true
if [ -s "$WORK/ignored" ]; then command grep -vxF -f "$WORK/ignored" "$WORK/all" > "$WORK/files" || true
else cp "$WORK/all" "$WORK/files"; fi
NFILES="$(wc -l < "$WORK/files" | tr -d ' ')"
echo "  scanning $NFILES files (gitignored excluded: $(wc -l < "$WORK/ignored" | tr -d ' '))"

GITLEAKS_JSON=""
if [ "${SNAPSHOT_NO_GITLEAKS:-0}" != 1 ] && command -v gitleaks >/dev/null 2>&1; then
  GITLEAKS_JSON="$WORK/gitleaks.json"
  echo "  secrets: gitleaks $(gitleaks version 2>/dev/null || echo '?')"
  if ! gitleaks detect --no-git --no-banner --source "$SRC" --report-format json \
        --report-path "$GITLEAKS_JSON" --exit-code 0 >/dev/null 2>&1; then
    die "gitleaks failed to run"
  fi
else
  echo "  secrets: gitleaks not installed, using built-in regex set"
fi

# The scanner. Words/paths are assembled from pieces so this script does not flag itself.
set +e
perl -e '
  use strict; use warnings;
  my ($root, $list, $allow, $gl) = @ARGV;
  my @allow;
  open my $A, "<", $allow or die "cannot read allowlist $allow: $!\n";
  while (<$A>) { chomp; next if /^\s*(#|$)/; my ($g, $lit) = split /\t/, $_;
    die "bad allowlist line $.: $_\n" unless defined $lit && length $lit;
    (my $re = quotemeta $g) =~ s/\\\*/.*/g; push @allow, [qr/^$re$/, $lit]; }
  close $A;
  # A hit is inert when its path matches an entry glob AND the hit lies inside an occurrence of that
  # entry literal on the same line (or the hit itself contains the literal).
  sub allowed { my ($f, $m, $line, $s) = @_; my $e = $s + length $m;
    for my $a (@allow) { next unless $f =~ $a->[0]; my $lit = $a->[1];
      return 1 if index($m, $lit) >= 0;
      my $i = -1; while (($i = index($line, $lit, $i + 1)) >= 0) { return 1 if $i <= $s && $i + length($lit) >= $e } }
    return 0 }
  my $secret = qr{(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-(?:proj-)?[A-Za-z0-9]{32,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|hooks\.slack\.com/services/T[A-Z0-9]+|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36})};
  my $p = "/" . "ho" . "me/|/" . "Us" . "ers/|/tmp/" . "claude-";
  my $localpath = qr{($p)};
  my $w = "content" . "[-_ ]?engine|\\bf" . "irm\\b";
  my $words = qr{($w)}i;
  my $gl_mode = defined $gl && length $gl;
  my ($hits, $ok) = (0, 0);
  my $report = sub { my ($f, $n, $kind, $m, $line, $s) = @_;
    if (allowed($f, $m, $line, $s)) { $ok++; return }
    $hits++; my $ctx = $line; $ctx =~ s/^\s+//; $ctx = substr($ctx, 0, 140);
    print "  HIT  $kind  $f:$n: $m\n         $ctx\n" };
  open my $L, "<", $list or die "$!\n";
  while (my $f = <$L>) { chomp $f; my $path = "$root/$f";
    next unless -f $path; next if -B $path;
    next if $f eq "scripts/submission-scan-allowlist.tsv";   # data file: repeats the allowed literals
    open my $F, "<", $path or die "$path: $!\n";
    while (my $line = <$F>) { chomp $line;
      unless ($gl_mode) { while ($line =~ /$secret/g) { $report->($f, $., "secret", $1, $line, $-[1]) } }
      # URLs are not local paths / words: blank them out (same length, so offsets still match $line).
      (my $nourl = $line) =~ s{\b[a-z][a-z0-9+.-]*://\S+}{" " x length($&)}gie;
      while ($nourl =~ /$localpath/g) { $report->($f, $., "local-path", $1, $line, $-[1]) }
      while ($nourl =~ /$words/g) { $report->($f, $., "internal-word", $1, $line, $-[1]) }
    }
    close $F }
  if ($gl_mode) { require JSON::PP; local $/; open my $G, "<", $gl or die "$gl: $!\n";
    my $txt = <$G>; my $arr = length $txt ? JSON::PP::decode_json($txt) : [];
    for my $r (@$arr) { (my $f = $r->{File}) =~ s{^\Q$root\E/?}{};
      $report->($f, $r->{StartLine} // 0, "secret[$r->{RuleID}]", $r->{Secret} // $r->{Match} // "", $r->{Match} // "", 0) } }
  print "  allowlisted (inert, see scripts/submission-scan-allowlist.tsv): $ok\n";
  exit($hits ? 1 : 0);
' "$SRC" "$WORK/files" "$REPO/$ALLOWLIST" "$GITLEAKS_JSON"
SCAN_RC=$?
set -e
[ "$SCAN_RC" = 0 ] || die "scan found the hits above; fix them on main (or, only for inert test data, add them to $ALLOWLIST) and re-run. No branch or tag was created."
echo "  ok  scan clean"

# --- 5. refs -----------------------------------------------------------------------------------------
step "5/6 create branch $BRANCH and tag $TAG (local only)"
if [ "$FORCE" = 1 ]; then git branch -f "$BRANCH" "$SNAP" >/dev/null; else git branch "$BRANCH" "$SNAP"; fi
TAG_MSG="SentinelProxy CrowdStrike Track 3 submission, snapshot of main @ $SHORT"
if [ "$FORCE" = 1 ]; then git tag -f -a "$TAG" -m "$TAG_MSG" "$SNAP" >/dev/null; else git tag -a "$TAG" -m "$TAG_MSG" "$SNAP"; fi
[ "$(git rev-list --count "$BRANCH")" = 1 ] || die "$BRANCH has more than one commit"
git diff --quiet "$HEAD_SHA" "$BRANCH" || die "$BRANCH tree differs from main"
echo "  ok  $BRANCH = $SNAP (1 commit, tree == main @ $SHORT), tag $TAG"

# --- 6. owner instructions -----------------------------------------------------------------------------
step "6/6 publish (repo OWNER runs this; this script pushed nothing)"
cat <<EOF
  Option A, gh CLI (creates the public repo, pushes the snapshot as its main branch + the tag):
    gh repo create <owner>/$REPO_NAME --public \\
      --description "SentinelProxy, CrowdStrike x SCU AI hackathon, Track 3"
    git push https://github.com/<owner>/$REPO_NAME.git $BRANCH:main
    git push https://github.com/<owner>/$REPO_NAME.git $TAG

  Option B, plain git (after creating an EMPTY public repo in the GitHub UI):
    git remote add submission https://github.com/<owner>/$REPO_NAME.git
    git push submission $BRANCH:main
    git push submission $TAG

  Do NOT push $BRANCH or $TAG to '$REMOTE' (that would not hide this repo's history anyway).
  Check the public repo shows exactly 1 commit: https://github.com/<owner>/$REPO_NAME/commits/main

  SUBMISSION.md link format (## Repository):
    https://github.com/<owner>/$REPO_NAME
    (pinned: https://github.com/<owner>/$REPO_NAME/tree/$TAG)
EOF
echo
echo "SNAPSHOT PASS: $BRANCH @ $SNAP, tag $TAG, tree == $REMOTE/main @ $SHORT"
