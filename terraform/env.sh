#!/usr/bin/env bash

set -e

dir=$(dirname $0)
source "$dir/.env"

cat <<EOF
{
  "cloudflare_api": "$cloudflare_api",
  "github_crashlog_pat": "$github_crashlog_pat"
}
EOF
