#!/usr/bin/env bash
# check-rate-limiters.sh — Verify route files reference rate limiting.
# Receives file paths as arguments from lint-staged.
# Only processes files matching server/routes/*.
# Checks that files defining routes reference some form of rate limiter.
# Note: A global generalLimiter is applied in server/index.ts covering all routes.
# This script warns if a route file has no file-level rate limiter reference,
# but only fails if the file has unauthenticated routes without rate limiting
# (since authenticated routes are covered by the global limiter).
# Exit 1 if a route file with public routes has no rate limiter.

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

  # Check if the file defines any routes
  if ! grep -qE 'router\.(get|post|put|delete|patch)\(' "$file"; then
    continue
  fi

  # Check if the file references any rate limiter
  if grep -qEi '(rateLimiter|rateLimit|Limiter|rate.limit)' "$file"; then
    # File has its own rate limiting — good
    continue
  fi

  # File has routes but no rate limiter reference.
  # Check if all routes are authenticated (covered by global generalLimiter).
  has_unauthed_routes=false
  while IFS= read -r line; do
    # Skip exempt public routes
    if echo "$line" | grep -qEi '(register|login|refresh|ws-ticket|health|ready)'; then
      continue
    fi
    # Check for authentication middleware
    if ! echo "$line" | grep -qE '(authenticateToken|authenticate)'; then
      has_unauthed_routes=true
      break
    fi
  done < <(grep -E 'router\.(get|post|put|delete|patch)\(' "$file" || true)

  if [ "$has_unauthed_routes" = true ]; then
    echo "ERROR: Route file $file has unauthenticated routes without rate limiting."
    echo "  Add a rate limiter to protect public endpoints."
    ERRORS=1
  fi
done

if [ "$ERRORS" -ne 0 ]; then
  echo ""
  echo "Missing rate limiters on public routes. See errors above."
  exit 1
fi

exit 0
