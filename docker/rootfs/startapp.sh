#!/bin/sh
set -u

export HOME=/config
cd /wikis 2>/dev/null || cd /config

exec /usr/bin/llm-wiki "$@"
