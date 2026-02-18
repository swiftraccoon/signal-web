#!/usr/bin/env bash
# check-unprotected-routes.sh — Detect routes without authentication middleware.
# Receives file paths as arguments from lint-staged.
# Only processes files matching server/routes/*.
# Exempt routes: /register, /login, /refresh, ws-ticket, health, ready
# Exit 1 if any unprotected route is found.

set -euo pipefail

ERRORS=0

for file in "$@"; do
  # Only check route files
  if ! echo "$file" | grep -qE 'server/routes/'; then
    continue
  fi

  # Skip non-existent files (deleted in staging)
  if [ ! -f "$file" ]; then
    continue
  fi

  # Find all route definitions: router.get, router.post, router.put, router.delete, router.patch
  # Then check if authenticateToken or authenticate is in the same route call
  while IFS= read -r line; do
    # Skip exempt routes
    if echo "$line" | grep -qEi "(register|login|refresh|ws-ticket|health|ready)"; then
      continue
    fi

    # Check if authenticateToken or authenticate is referenced in the route handler chain
    if ! echo "$line" | grep -qE '(authenticateToken|authenticate)'; then
      # Get line number for better error reporting
      lineno=$(grep -nF "$line" "$file" | head -1 | cut -d: -f1)
      echo "ERROR: Unprotected route in $file:$lineno"
      echo "  $line"
      ERRORS=1
    fi
  done < <(grep -E 'router\.(get|post|put|delete|patch)\(' "$file" || true)
done

if [ "$ERRORS" -ne 0 ]; then
  echo ""
  echo "Unprotected routes detected. Add authenticateToken middleware."
  exit 1
fi

exit 0
