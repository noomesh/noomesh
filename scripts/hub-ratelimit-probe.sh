#!/usr/bin/env bash
# Print the Docker Hub pull allowance the DHI_USERNAME/DHI_TOKEN credential
# earns, from Docker's rate-limit preview repository (reading it costs no
# pull). 100 per 6h means the credential is treated as anonymous; 200 per 6h
# is an authenticated free account. The token is used in the request only and
# never printed. Informational: always exits 0.
set -u
if [ -z "${DHI_TOKEN:-}" ] || [ -z "${DHI_USERNAME:-}" ]; then
  echo "hub-ratelimit-probe: no credentials, skipped"
  exit 0
fi
tok="$(curl -fsS -u "${DHI_USERNAME}:${DHI_TOKEN}" \
  'https://auth.docker.io/token?service=registry.docker.io&scope=repository:ratelimitpreview/test:pull' \
  | jq -r .token 2>/dev/null)" || tok=""
if [ -z "$tok" ] || [ "$tok" = null ]; then
  echo "hub-ratelimit-probe: token request failed"
  exit 0
fi
hdr="$(curl -sI -H "Authorization: Bearer ${tok}" \
  https://registry-1.docker.io/v2/ratelimitpreview/test/manifests/latest \
  | tr -d '\r' | grep -i '^ratelimit-')"
echo "hub-ratelimit-probe (authenticated): ${hdr:-no ratelimit headers}"
exit 0
