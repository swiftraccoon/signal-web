#!/usr/bin/env bash
# check-crypto-misuse.sh — Detect crypto anti-patterns in staged files.
# Receives file paths as arguments from lint-staged.
# Skips test files, node_modules, dist.
# Exit 1 if any crypto anti-pattern is found.

set -euo pipefail

ERRORS=0

for file in "$@"; do
  # Skip test files, node_modules, dist
  if echo "$file" | grep -qE '(\.test\.|\.spec\.|__tests__|tests/|test/|node_modules/|dist/)'; then
    continue
  fi

  # Skip non-existent files (deleted in staging)
  if [ ! -f "$file" ]; then
    continue
  fi

  # Pattern 1: MD5 usage
  if grep -nE "createHash\(['\"]md5['\"]\)" "$file" | grep -qvE '^\s*//|^\s*\*|^\s*#'; then
    echo "ERROR: MD5 is broken — use SHA-256 or better in $file:"
    grep -nE "createHash\(['\"]md5['\"]\)" "$file" | grep -vE '^\s*//|^\s*\*|^\s*#' || true
    ERRORS=1
  fi

  # Pattern 2: SHA-1 usage
  if grep -nE "createHash\(['\"]sha1['\"]\)" "$file" | grep -qvE '^\s*//|^\s*\*|^\s*#'; then
    echo "ERROR: SHA-1 is deprecated — use SHA-256 or better in $file:"
    grep -nE "createHash\(['\"]sha1['\"]\)" "$file" | grep -vE '^\s*//|^\s*\*|^\s*#' || true
    ERRORS=1
  fi

  # Pattern 3: ECB mode ciphers
  if grep -nEi 'ecb' "$file" | grep -qvE '^\s*//|^\s*\*|^\s*#'; then
    echo "ERROR: ECB mode is insecure in $file:"
    grep -nEi 'ecb' "$file" | grep -vE '^\s*//|^\s*\*|^\s*#' || true
    ERRORS=1
  fi

  # Pattern 4: Math.random() in crypto-relevant files
  # Only flag if the file also references crypto/token/secret/password/key/auth/session/nonce/salt
  if grep -qE 'Math\.random\(\)' "$file"; then
    if grep -qEi '(crypto|token|secret|password|key|auth|session|nonce|salt)' "$file"; then
      if grep -nE 'Math\.random\(\)' "$file" | grep -qvE '^\s*//|^\s*\*|^\s*#'; then
        echo "ERROR: Math.random() used in crypto-relevant file $file (use crypto.getRandomValues or crypto.randomBytes):"
        grep -nE 'Math\.random\(\)' "$file" | grep -vE '^\s*//|^\s*\*|^\s*#' || true
        ERRORS=1
      fi
    fi
  fi

  # Pattern 5: Deprecated createCipher() without IV
  # createCipher( is deprecated; createCipheriv( is the correct API
  if grep -nE 'createCipher\(' "$file" | grep -qvE 'createCipheriv|^\s*//|^\s*\*|^\s*#'; then
    echo "ERROR: Deprecated createCipher() without IV in $file (use createCipheriv):"
    grep -nE 'createCipher\(' "$file" | grep -vE 'createCipheriv|^\s*//|^\s*\*|^\s*#' || true
    ERRORS=1
  fi

  # Pattern 6: Hardcoded IV/nonce — iv or nonce assigned to Buffer.from([...]) or new Uint8Array([...])
  if grep -nE '\b(iv|nonce)\s*=\s*(Buffer\.from\(\[|new\s+Uint8Array\(\[)' "$file" | grep -qvE '^\s*//|^\s*\*|^\s*#'; then
    echo "ERROR: Hardcoded IV/nonce detected in $file (IVs must be randomly generated):"
    grep -nE '\b(iv|nonce)\s*=\s*(Buffer\.from\(\[|new\s+Uint8Array\(\[)' "$file" | grep -vE '^\s*//|^\s*\*|^\s*#' || true
    ERRORS=1
  fi
done

if [ "$ERRORS" -ne 0 ]; then
  echo ""
  echo "Crypto anti-patterns detected. See errors above."
  exit 1
fi

exit 0
