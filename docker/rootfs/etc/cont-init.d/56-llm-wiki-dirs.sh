#!/bin/sh
# Default location for wiki projects (bind-mounted from the host).
set -e
set -u
mkdir -p /wikis
chown "${USER_ID}:${GROUP_ID}" /wikis
