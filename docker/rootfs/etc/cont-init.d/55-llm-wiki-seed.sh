#!/bin/sh
#
# Seed LLM Wiki's settings store (tauri-plugin-store app-state.json) so the
# app uses copilot-api for both chat/ingest and embeddings out of the box.
#
# LLM_WIKI_PROVIDER_SEED:
#   missing (default) - only fill settings that are not set yet; changes made
#                       in the Settings UI are kept across restarts.
#   force             - re-apply the copilot-api provider settings on every
#                       start (other custom presets/settings are preserved).
#   off               - never touch the store.

set -e
set -u

MODE="${LLM_WIKI_PROVIDER_SEED:-missing}"
if [ "${MODE}" = "off" ]; then
    echo "LLM Wiki provider seeding disabled."
    exit 0
fi

STORE_DIR="${XDG_DATA_HOME:-/config/xdg/data}/com.llmwiki.app"
STORE_FILE="${STORE_DIR}/app-state.json"
PRESET_ID="custom-copilot-api"

mkdir -p "${STORE_DIR}"
CURRENT="{}"
if [ -s "${STORE_FILE}" ]; then
    if jq -e 'type == "object"' "${STORE_FILE}" >/dev/null 2>&1; then
        CURRENT="$(cat "${STORE_FILE}")"
    else
        echo "WARNING: ${STORE_FILE} is not valid JSON; backing it up and reseeding."
        cp "${STORE_FILE}" "${STORE_FILE}.invalid.$(date +%s)"
    fi
fi

SEED="$(jq -n \
    --arg pid "${PRESET_ID}" \
    --arg preset_label "${LLM_WIKI_LLM_LABEL:-Copilot API}" \
    --arg base "${LLM_WIKI_LLM_BASE_URL:-http://127.0.0.1:4141/v1}" \
    --arg key "${LLM_WIKI_LLM_API_KEY:-copilot-api}" \
    --arg model "${LLM_WIKI_LLM_MODEL:-claude-sonnet-5-5}" \
    --argjson ctx "${LLM_WIKI_LLM_CONTEXT_SIZE:-400000}" \
    --arg emb_url "${LLM_WIKI_EMBEDDING_URL:-http://127.0.0.1:4141/v1/embeddings}" \
    --arg emb_key "${LLM_WIKI_EMBEDDING_API_KEY:-copilot-api}" \
    --arg emb_model "${LLM_WIKI_EMBEDDING_MODEL:-text-embedding-3-small}" \
    '{
        customLlmPresets: [{id: $pid, label: $preset_label}],
        providerConfigs: {
            ($pid): {
                apiKey: $key,
                model: $model,
                baseUrl: $base,
                apiMode: "chat_completions",
                maxContextSize: $ctx
            }
        },
        activePresetId: $pid,
        llmConfig: {
            provider: "custom",
            apiKey: $key,
            model: $model,
            ollamaUrl: "http://localhost:11434",
            customEndpoint: $base,
            maxContextSize: $ctx,
            apiMode: "chat_completions",
            reasoning: {mode: "auto"},
            ingestReasoning: {mode: "off"},
            localCliIsolation: false
        },
        embeddingConfig: {
            enabled: true,
            endpoint: $emb_url,
            apiKey: $emb_key,
            model: $emb_model
        },
        generalConfig: {
            autostart: false,
            closeBehavior: "exit"
        }
    }')"

if [ "${MODE}" = "force" ]; then
    # Seed wins for the managed keys; keep any other custom presets.
    FILTER='. as [$cur, $seed]
        | ($cur * $seed)
        | .customLlmPresets = ((($cur.customLlmPresets // []) | map(select(.id != $seed.activePresetId))) + $seed.customLlmPresets)'
else
    # Existing values win; seed only fills what is missing. The preset list
    # must still contain the copilot-api preset its providerConfigs refer to.
    FILTER='. as [$cur, $seed]
        | ($seed * $cur)
        | .customLlmPresets = (($cur.customLlmPresets // []) as $p
            | if any($p[]; .id == $seed.activePresetId) then $p else $p + $seed.customLlmPresets end)'
fi

TMP="$(mktemp "${STORE_DIR}/.app-state.XXXXXX")"
jq -n --argjson cur "${CURRENT}" --argjson seed "${SEED}" "[\$cur, \$seed] | ${FILTER}" > "${TMP}"

# Default project (e.g. the mounted knowledge base): open it on launch unless a
# last project is already recorded, and keep it in the recent-projects list.
PROJECT_PATH="${LLM_WIKI_DEFAULT_PROJECT:-}"
if [ -n "${PROJECT_PATH}" ] && [ -f "${PROJECT_PATH}/.llm-wiki/project.json" ]; then
    PROJECT_ID="$(jq -r '.id // empty' "${PROJECT_PATH}/.llm-wiki/project.json")"
    if [ -n "${PROJECT_ID}" ]; then
        PROJECT="$(jq -n --arg id "${PROJECT_ID}" --arg name "$(basename "${PROJECT_PATH}")" --arg path "${PROJECT_PATH}" \
            '{id: $id, name: $name, path: $path}')"
        TMP2="$(mktemp "${STORE_DIR}/.app-state.XXXXXX")"
        jq --argjson p "${PROJECT}" --arg force "${MODE}" '
            (if .lastProject == null or $force == "force" then .lastProject = $p else . end)
            | .recentProjects = ([$p] + ((.recentProjects // []) | map(select(.path != $p.path))))[:10]
        ' "${TMP}" > "${TMP2}"
        mv "${TMP2}" "${TMP}"
    fi
elif [ -n "${PROJECT_PATH}" ]; then
    echo "WARNING: LLM_WIKI_DEFAULT_PROJECT=${PROJECT_PATH} is not an LLM Wiki project (missing .llm-wiki/project.json)."
fi

mv "${TMP}" "${STORE_FILE}"
chown -R "${USER_ID}:${GROUP_ID}" "${STORE_DIR}"
chmod 600 "${STORE_FILE}"

echo "LLM Wiki provider settings seeded (${MODE}): $(jq -c '{model: .llmConfig.model, endpoint: .llmConfig.customEndpoint, embedding: .embeddingConfig.model, project: .lastProject.path}' "${STORE_FILE}")"
