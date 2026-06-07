#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <task-file>" >&2
  exit 2
fi

task_file="$1"

if [ ! -f "$task_file" ]; then
  echo "task file not found: $task_file" >&2
  exit 2
fi

missing=0

check_pattern() {
  pattern="$1"
  if ! grep -Fq -- "$pattern" "$task_file"; then
    echo "missing required task field: $pattern" >&2
    missing=1
  fi
}

check_pattern "## Objective"
check_pattern "## Owned Paths"
check_pattern "## Avoid Paths"
check_pattern "Assumptions:"
check_pattern "Ambiguities:"
check_pattern "Success criteria:"
check_pattern "-> verify"
check_pattern "## Done Criteria"
check_pattern "## Final Report"
check_pattern "Files changed"
check_pattern "Tests run"
check_pattern "Risks"

if [ "$missing" -ne 0 ]; then
  exit 1
fi

echo "task protocol fields present: $task_file"
