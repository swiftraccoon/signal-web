#!/usr/bin/env bash
# check-secrets.sh — Detect hardcoded secrets in staged files.
# Receives file paths as arguments from lint-staged.
# Skips test files.
# Exit 1 if any hardcoded secret pattern is found.

set -euo pipefail

ERRORS=0

for file in "$@"; do
  # Skip test files
  if echo "$file" | grep -qE '(\.test\.|\.spec\.|__tests__|tests/|test/)'; then
    continue
  fi

  # Skip non-existent files (deleted in staging)
  if [ ! -f "$file" ]; then
    continue
  fi

  # Pattern 1: JWT_SECRET assigned to a string literal (not process.env)
  # Match: JWT_SECRET = 'xxx' or JWT_SECRET = "xxx" but NOT process.env.JWT_SECRET
  # Also skip lines with "example" (case-insensitive)
  if grep -nE "JWT_SECRET\s*[:=]\s*['\"]" "$file" | grep -viE 'process\.env|example' | grep -qvE '^\s*//|^\s*\*|^\s*#'; then
    echo "ERROR: Possible hardcoded JWT_SECRET in $file:"
    grep -nE "JWT_SECRET\s*[:=]\s*['\"]" "$file" | grep -viE 'process\.env|example' | grep -vE '^\s*//|^\s*\*|^\s*#' || true
    ERRORS=1
  fi

  # Pattern 2: BEGIN PRIVATE KEY blocks
  if grep -nE 'BEGIN\s+(RSA\s+)?PRIVATE\s+KEY' "$file" | grep -qviE 'example'; then
    echo "ERROR: Private key found in $file:"
    grep -nE 'BEGIN\s+(RSA\s+)?PRIVATE\s+KEY' "$file" | grep -viE 'example' || true
    ERRORS=1
  fi

  # Pattern 3: API key assignments with 20+ char string values (not process.env)
  # Match patterns like: API_KEY = 'xxxxxxxxxxxxxxxxxxxx' or apiKey = "xxxxxxxxxxxxxxxxxxxx"
  # Skip process.env references and comments with "example"
  if grep -nEi "(api[_-]?key|api[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"][^'\"]{20,}['\"]" "$file" | grep -viE 'process\.env|example' | grep -qvE '^\s*//|^\s*\*|^\s*#'; then
    echo "ERROR: Possible hardcoded API key in $file:"
    grep -nEi "(api[_-]?key|api[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"][^'\"]{20,}['\"]" "$file" | grep -viE 'process\.env|example' | grep -vE '^\s*//|^\s*\*|^\s*#' || true
    ERRORS=1
  fi
done

if [ "$ERRORS" -ne 0 ]; then
  echo ""
  echo "Hardcoded secrets detected. Use environment variables instead."
  exit 1
fi

exit 0
