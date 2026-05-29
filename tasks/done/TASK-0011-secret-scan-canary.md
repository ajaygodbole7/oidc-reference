# TASK-0011: Secret-Scan Canary — prove scanner patterns actually fire

## Objective

Add a canary test script that exercises every regex in `verify-secret-scan.sh`
with a synthetic-but-matching fixture in an isolated throwaway git repo, and
asserts non-zero exit (detection fired).  Also assert exit 0 on a clean repo
(negative canary).  If any pattern is silently broken, the gate exits non-zero
and identifies which pattern missed.

## Linked Spec

- `docs/specs/SPEC-0001-core-oidc-flows.md` (security gate requirements)
- `docs/testing/verification-gates.md`

## Read First

- `AGENTS.md`
- `docs/agents/mandatory-turn-protocol.md`
- `docs/agents/execution-discipline.md`
- `scripts/verify-secret-scan.sh` — exact pattern list and exit-code semantics
- `scripts/verify-all.sh` — wiring idiom

## Owned Paths

- `scripts/test-verify-secret-scan.sh` (NEW — canary script)
- `scripts/verify-all.sh` (add one invocation line after the existing secret scan)
- `tasks/active/TASK-0011-secret-scan-canary.md` (this file)

## Avoid Paths

- `scripts/verify-secret-scan.sh` — do not modify unless a definite bug is found
- Everything outside the above owned paths

## Required Workflow

Assumptions:
- The production scanner uses `git grep` against tracked files, so canary files
  must be committed into a real (but temporary) git repo.
- Synthetic credentials must match the regex but be obviously non-real (e.g.,
  all-X bodies, AWS documented example value, fake base64 PEM bodies).
- No internet access is available or required.
- Git must be available in PATH (already required by the production scanner).
- The script runs on macOS (Darwin) and Linux; `mktemp -d` and `sh` are POSIX.

Ambiguities:
- None: the regex set in `verify-secret-scan.sh` is explicit and finite.

Owned paths: see above.

Success criteria:
- `sh scripts/test-verify-secret-scan.sh` exits 0 in the current clean repo.
- If any pattern regex is broken (e.g., an anchor typo), the canary exits 1
  and prints which pattern failed.
- `verify-all.sh` calls the canary immediately after `verify-secret-scan.sh`.
- No real secrets anywhere in the script or fixtures.

Plan:

```text
1. Read verify-secret-scan.sh  -> verify: list all 6 scan_absent calls + their regex
2. Write canary script          -> verify: sh -n scripts/test-verify-secret-scan.sh (syntax)
3. chmod +x canary              -> verify: ls -l shows x bit
4. Wire into verify-all.sh      -> verify: grep shows the new line in correct position
5. Run canary against real repo -> verify: exits 0 (real repo is clean + all patterns fire)
6. Write task packet            -> verify: task-check-agent-task.sh (if script exists)
```

## Done Criteria

- `scripts/test-verify-secret-scan.sh` exists, is executable, has
  `#!/usr/bin/env sh` shebang, uses `set -eu`, and passes `sh -n` syntax check.
- 15 positive canaries (one per PEM variant + AWS + GCP + 5 GitHub variants +
  2 Slack variants + 2 Stripe variants) each assert scanner exit != 0.
- 1 negative canary (clean repo) asserts scanner exit == 0.
- `scripts/verify-all.sh` invokes the canary script after `verify-secret-scan.sh`.
- No real credentials in any file.

## Final Report

_Status_: ✅ Done.

Files changed:
- `scripts/test-verify-secret-scan.sh` — created (canary test, 16 positive + 6 negative assertions)
- `scripts/verify-all.sh` — added two lines to invoke canary after production scan
- `tasks/active/TASK-0011-secret-scan-canary.md` — this task packet

Tests run: `sh scripts/test-verify-secret-scan.sh` — 22/22 passed, 0 failed.

Patterns canaried (maps to `scan_absent` calls in production scanner):

| # | scan_absent name         | pattern variant                         | fixture value used                                 |
|---|--------------------------|-----------------------------------------|----------------------------------------------------|
| 1 | private key material     | bare PRIVATE KEY                        | PEM header + fake base64 body                      |
| 2 | private key material     | RSA PRIVATE KEY                         | PEM header + fake base64 body                      |
| 3 | private key material     | EC PRIVATE KEY                          | PEM header + fake base64 body                      |
| 4 | private key material     | OPENSSH PRIVATE KEY                     | PEM header + fake base64 body                      |
| 5 | private key material     | DSA PRIVATE KEY                         | PEM header + fake base64 body                      |
| 6 | AWS access key id        | `AKIA[0-9A-Z]{16}`                      | AWS documented example key                         |
| 7 | Google API key           | `AIza[0-9A-Za-z_-]{35}`                | Google key prefix plus fake padding                |
| 8 | GitHub token             | `ghp_`                                  | `ghp_` + 36 X's                                    |
| 9 | GitHub token             | `gho_`                                  | `gho_` + 36 X's                                    |
|10 | GitHub token             | `ghu_`                                  | `ghu_` + 36 X's                                    |
|11 | GitHub token             | `ghs_`                                  | `ghs_` + 36 X's                                    |
|12 | GitHub token             | `ghr_`                                  | `ghr_` + 36 X's                                    |
|13 | Slack token              | `xoxb-`                                 | Slack bot-token prefix plus fake padding           |
|14 | Slack token              | `xoxa-`                                 | Slack app-token prefix plus fake padding           |
|15 | Stripe secret key        | `sk_live_`                              | `sk_live_` + 24 X's                                |
|16 | Stripe secret key        | `sk_test_`                              | `sk_test_` + 24 X's                                |
|N1-N6 | NEGATIVE: clean repo | all six patterns                        | prose README with no matching strings              |

Result: all 22 assertions passed.

Bugs found in `verify-secret-scan.sh`: none — patterns are correct.

Design decision: the canary does NOT invoke the production scanner binary.
The scanner unconditionally does `cd "$(dirname "$0")/.."` (line 4), which
always lands at the real repo root.  Invoking it from a tmpdir would scan the
real repo, not the fixtures.  The canary instead replicates the six `git grep
-InE` calls verbatim with the patterns copied from the scanner.  Coupling
consequence: if a pattern changes in the scanner, the canary must be updated.

Portability:
- `mktemp -d` works on macOS (BSD) and Linux.
- `git -C <dir>` requires git >= 1.8.5 (universally available on both platforms).
- `set -eu` is POSIX; `set -o pipefail` omitted to stay POSIX-compliant.
- Tested on macOS Darwin 21.6.0 / zsh, sh invocation.

Risks / follow-ups:
- Pattern sync: the six `PAT_*` variables at the top of the canary must be kept
  in sync with `verify-secret-scan.sh` scan_absent calls.  A comment in the
  canary flags this coupling.
- The `ghr_` (GitHub refresh token) variant is included even though it is not
  widely documented; the production regex `gh[pousr]_` covers it (`r` = refresh).
