#!/bin/sh
# Publishes the VSDA Deep Agent app URL to the web pages. The login page and
# the noVNC control bar link to it for registration, password resets, and
# account changes; nginx substitutes the LLM_WIKI_VSDA_APP_URL placeholder
# the same way the base image substitutes APP_NAME.
set -e
set -u

SUB_FILTER_CONF=/var/tmp/nginx/sub_filter.conf
APP_URL="${LLM_WIKI_VSDA_APP_URL:-https://agent.vsda.top/chat}"
APP_URL="${APP_URL%/}"

case "${APP_URL}" in
    http://?*|https://?*) ;;
    *)
        echo "ERROR: LLM_WIKI_VSDA_APP_URL must be an http(s) URL: ${APP_URL}"
        exit 1
        ;;
esac
# Quotes, $, and whitespace would break the nginx directive or the HTML.
if printf '%s' "${APP_URL}" | grep -q "[[:space:]'\"\\\$<>\`\\\\]"; then
    echo "ERROR: LLM_WIKI_VSDA_APP_URL contains unsupported characters: ${APP_URL}"
    exit 1
fi

printf "sub_filter 'LLM_WIKI_VSDA_APP_URL' '%s';\n" "${APP_URL}" >> "${SUB_FILTER_CONF}"

if is-bool-val-true "${WEB_AUTHENTICATION:-0}"; then
    echo "Web sign-in uses VSDA Deep Agent accounts (${LLM_WIKI_VSDA_API_URL:-http://127.0.0.1:8000}); accounts are managed at ${APP_URL}/"
fi
