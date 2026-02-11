#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="stevio2d"
REPO_NAME="ai-chat-shell"
REPO_REF="${REPO_REF:-main}"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_REF}"

DEFAULT_BASE_URL="https://openrouter.ai/api/v1"
DEFAULT_MODEL="google/gemini-2.5-flash-lite"
DEFAULT_ALIAS="ai"
DEFAULT_OLLAMA_BASE_URL="http://127.0.0.1:11434/v1"
DEFAULT_OLLAMA_MODEL="llama3.2"
DEFAULT_LMSTUDIO_BASE_URL="http://127.0.0.1:1234/v1"
DEFAULT_LMSTUDIO_MODEL="local-model"

ORIGINAL_API_KEY="${OPENROUTER_API_KEY:-}"
API_KEY="${ORIGINAL_API_KEY}"
MODEL="${AI_MODEL:-$DEFAULT_MODEL}"
BASE_URL="${AI_BASE_URL:-$DEFAULT_BASE_URL}"
ALIAS_NAME="${AI_ALIAS:-$DEFAULT_ALIAS}"
PROVIDER="${AI_PROVIDER:-openrouter}"
MODEL_EXPLICIT="0"
BASE_URL_EXPLICIT="0"
if [[ -n "${AI_MODEL:-}" ]]; then
  MODEL_EXPLICIT="1"
fi
if [[ -n "${AI_BASE_URL:-}" ]]; then
  BASE_URL_EXPLICIT="1"
fi

INSTALL_DIR="${HOME}/.local/share/ai-chat-shell"
BIN_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/ai-chat-shell"
ENV_FILE="${CONFIG_DIR}/env"
SHELL_RC="${HOME}/.zshrc"

AUTO_COMMAND="1"
AUTO_EXEC="0"
EXPECTED_AICHAT_SHA256="${AI_AICHAT_SHA256:-}"

usage() {
  cat <<'EOF'
Usage:
  install.sh [--model MODEL] [--alias NAME] [--base-url URL] [--provider NAME] [--ollama] [--lmstudio]
             [--ref REF] [--aichat-sha256 HEX] [--no-auto-command] [--auto-exec]
             [--from-query "model=...&alias=..."]

Examples:
  export OPENROUTER_API_KEY="sk-or-..."
  curl -fsSL https://raw.githubusercontent.com/stevio2d/ai-chat-shell/main/install.sh | bash -s -- \
    --model "google/gemini-2.5-flash-lite" --alias "ai"

  curl -fsSL https://raw.githubusercontent.com/stevio2d/ai-chat-shell/main/install.sh | bash -s -- \
    --provider "ollama" --model "llama3.2" --alias "ai"

  curl -fsSL https://raw.githubusercontent.com/stevio2d/ai-chat-shell/main/install.sh | bash -s -- \
    --from-query "provider=lmstudio&model=local-model&alias=ai&auto_exec=1"
EOF
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return
  fi
  echo "No SHA-256 tool found (need sha256sum or shasum)." >&2
  return 1
}

urldecode() {
  local data="${1//+/ }"
  printf '%b' "${data//%/\\x}"
}

base_url_host() {
  local input="$1"
  local without_scheme="${input#*://}"
  local host_port="${without_scheme%%/*}"
  local host="${host_port%%:*}"
  printf '%s' "${host}" | tr '[:upper:]' '[:lower:]'
}

is_openrouter_base_url() {
  local host
  host="$(base_url_host "$1")"
  [[ "${host}" == "openrouter.ai" || "${host}" == *.openrouter.ai ]]
}

apply_provider_preset() {
  local provider_input="$1"
  local provider
  provider="$(printf '%s' "${provider_input}" | tr '[:upper:]' '[:lower:]')"
  case "${provider}" in
    openrouter)
      PROVIDER="openrouter"
      if [[ "${BASE_URL_EXPLICIT}" == "0" ]]; then
        BASE_URL="${DEFAULT_BASE_URL}"
      fi
      if [[ "${MODEL_EXPLICIT}" == "0" ]]; then
        MODEL="${DEFAULT_MODEL}"
      fi
      API_KEY="${ORIGINAL_API_KEY}"
      ;;
    ollama)
      PROVIDER="ollama"
      if [[ "${BASE_URL_EXPLICIT}" == "0" ]]; then
        BASE_URL="${DEFAULT_OLLAMA_BASE_URL}"
      fi
      if [[ "${MODEL_EXPLICIT}" == "0" ]]; then
        MODEL="${DEFAULT_OLLAMA_MODEL}"
      fi
      API_KEY=""
      ;;
    lmstudio)
      PROVIDER="lmstudio"
      if [[ "${BASE_URL_EXPLICIT}" == "0" ]]; then
        BASE_URL="${DEFAULT_LMSTUDIO_BASE_URL}"
      fi
      if [[ "${MODEL_EXPLICIT}" == "0" ]]; then
        MODEL="${DEFAULT_LMSTUDIO_MODEL}"
      fi
      API_KEY=""
      ;;
    *)
      echo "Unsupported provider: ${provider_input}. Use openrouter, ollama, or lmstudio." >&2
      exit 1
      ;;
  esac
}

parse_query() {
  local query="${1#*\?}"
  local pair key value
  IFS='&' read -r -a items <<< "${query}"
  for pair in "${items[@]}"; do
    key="${pair%%=*}"
    value="${pair#*=}"
    value="$(urldecode "${value}")"
    case "${key}" in
      api_key)
        echo "Ignoring api_key in query string for security; set OPENROUTER_API_KEY in your environment instead." >&2
        ;;
      model)
        MODEL="${value}"
        MODEL_EXPLICIT="1"
        ;;
      alias) ALIAS_NAME="${value}" ;;
      base_url)
        BASE_URL="${value}"
        BASE_URL_EXPLICIT="1"
        ;;
      provider) apply_provider_preset "${value}" ;;
      ref) REPO_REF="${value}" ;;
      aichat_sha256) EXPECTED_AICHAT_SHA256="${value}" ;;
      auto_command) [[ "${value}" == "0" ]] && AUTO_COMMAND="0" ;;
      auto_exec) [[ "${value}" == "1" ]] && AUTO_EXEC="1" ;;
      *) ;;
    esac
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --model)
      MODEL="${2:-}"
      MODEL_EXPLICIT="1"
      shift 2
      ;;
    --alias)
      ALIAS_NAME="${2:-}"
      shift 2
      ;;
    --base-url)
      BASE_URL="${2:-}"
      BASE_URL_EXPLICIT="1"
      shift 2
      ;;
    --provider)
      apply_provider_preset "${2:-}"
      shift 2
      ;;
    --ollama)
      apply_provider_preset "ollama"
      shift
      ;;
    --lmstudio)
      apply_provider_preset "lmstudio"
      shift
      ;;
    --ref)
      REPO_REF="${2:-}"
      shift 2
      ;;
    --aichat-sha256)
      EXPECTED_AICHAT_SHA256="${2:-}"
      shift 2
      ;;
    --no-auto-command)
      AUTO_COMMAND="0"
      shift
      ;;
    --auto-exec)
      AUTO_EXEC="1"
      shift
      ;;
    --from-query)
      parse_query "${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      if [[ "$1" == *"="* || "$1" == *"?"* ]]; then
        parse_query "$1"
        shift
      else
        echo "Unknown argument: $1" >&2
        usage
        exit 1
      fi
      ;;
  esac
done

FIX_ALIAS_NAME="${ALIAS_NAME}fix"

if [[ ! "${ALIAS_NAME}" =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ ]]; then
  echo "Invalid alias name: ${ALIAS_NAME}" >&2
  exit 1
fi

RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_REF}"
USES_OPENROUTER="0"
if is_openrouter_base_url "${BASE_URL}"; then
  USES_OPENROUTER="1"
fi

mkdir -p "${INSTALL_DIR}" "${BIN_DIR}" "${CONFIG_DIR}"

curl -fsSL "${RAW_BASE}/aichat/aichat.py" -o "${INSTALL_DIR}/aichat.py"
chmod +x "${INSTALL_DIR}/aichat.py"

if [[ -n "${EXPECTED_AICHAT_SHA256}" ]]; then
  ACTUAL_AICHAT_SHA256="$(sha256_file "${INSTALL_DIR}/aichat.py")"
  EXPECTED_LOWER="$(printf '%s' "${EXPECTED_AICHAT_SHA256}" | tr '[:upper:]' '[:lower:]')"
  ACTUAL_LOWER="$(printf '%s' "${ACTUAL_AICHAT_SHA256}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${ACTUAL_LOWER}" != "${EXPECTED_LOWER}" ]]; then
    echo "aichat.py checksum mismatch." >&2
    echo "  expected: ${EXPECTED_AICHAT_SHA256}" >&2
    echo "  actual:   ${ACTUAL_AICHAT_SHA256}" >&2
    exit 1
  fi
fi

{
  printf 'export AI_BASE_URL=%q\n' "${BASE_URL}"
  printf 'export AI_MODEL=%q\n' "${MODEL}"
  printf 'export AI_PROVIDER=%q\n' "${PROVIDER}"
  printf 'export OPENROUTER_HTTP_REFERER=%q\n' "https://localhost"
  printf 'export OPENROUTER_APP_NAME=%q\n' "ai-chat-shell"
  if [[ "${USES_OPENROUTER}" == "1" && -n "${API_KEY}" ]]; then
    printf 'export OPENROUTER_API_KEY=%q\n' "${API_KEY}"
  elif [[ "${USES_OPENROUTER}" == "1" ]]; then
    echo '# export OPENROUTER_API_KEY="sk-or-..."'
  else
    echo '# OPENROUTER_API_KEY is not required for this AI_BASE_URL'
  fi
} > "${ENV_FILE}"
chmod 600 "${ENV_FILE}"

RUN_FLAGS=()
if [[ "${AUTO_COMMAND}" == "1" ]]; then
  RUN_FLAGS+=(--auto-command)
fi
if [[ "${AUTO_EXEC}" == "1" ]]; then
  RUN_FLAGS+=(--exec)
fi

cat > "${BIN_DIR}/${ALIAS_NAME}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
fi
exec python3 "${INSTALL_DIR}/aichat.py" ${RUN_FLAGS[*]} "\$@"
EOF
chmod +x "${BIN_DIR}/${ALIAS_NAME}"

cat > "${BIN_DIR}/${ALIAS_NAME}c" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
fi
exec python3 "${INSTALL_DIR}/aichat.py" -c "\$@"
EOF
chmod +x "${BIN_DIR}/${ALIAS_NAME}c"

START_MARK="# >>> ai-chat-shell >>>"
END_MARK="# <<< ai-chat-shell <<<"

if [[ ! -f "${SHELL_RC}" ]]; then
  touch "${SHELL_RC}"
fi

if grep -Fq "${START_MARK}" "${SHELL_RC}"; then
  TMP_RC="$(mktemp)"
  awk -v start="${START_MARK}" -v end="${END_MARK}" '
    $0 == start { in_block = 1; next }
    $0 == end { in_block = 0; next }
    !in_block { print }
  ' "${SHELL_RC}" > "${TMP_RC}"
  mv "${TMP_RC}" "${SHELL_RC}"
fi

{
  echo
  echo "${START_MARK}"
  echo 'export PATH="$HOME/.local/bin:$PATH"'
  echo 'if [ -f "$HOME/.config/ai-chat-shell/env" ]; then'
  echo '  source "$HOME/.config/ai-chat-shell/env"'
  echo 'fi'
  echo "unalias ${ALIAS_NAME} 2>/dev/null || true"
  echo "unalias ${ALIAS_NAME}c 2>/dev/null || true"
  echo "unalias ${FIX_ALIAS_NAME} 2>/dev/null || true"
  echo 'unalias aifix 2>/dev/null || true'
  echo 'unset -f __aichat_fix 2>/dev/null || true'
  echo 'unset -f aifix 2>/dev/null || true'
  echo "alias ${ALIAS_NAME}=\"\$HOME/.local/bin/${ALIAS_NAME}\""
  echo "alias ${ALIAS_NAME}c=\"\$HOME/.local/bin/${ALIAS_NAME}c\""
  echo "alias ${FIX_ALIAS_NAME}=\"__aichat_fix\""
  echo '__aichat_fix() {'
  echo '  local prev_status=$?'
  echo '  local last_cmd'
  echo '  local last_cmd_file'
  echo '  local safe_last_cmd'
  echo '  local note'
  echo '  local prompt'
  echo ''
  echo '  last_cmd_file="${AI_LAST_COMMAND_FILE:-$HOME/.config/ai-chat-shell/last_command}"'
  echo '  if [[ -f "$last_cmd_file" ]]; then'
  echo '    last_cmd=$(tail -n 1 "$last_cmd_file" 2>/dev/null | sed "s/^[[:space:]]*//; s/[[:space:]]*$//")'
  echo '  fi'
  echo '  if [[ -z "$last_cmd" ]]; then'
  echo "    last_cmd=\$(fc -ln -20 2>/dev/null | sed '/^[[:space:]]*$/d' | sed '/^[[:space:]]*\\(${ALIAS_NAME}\\|${ALIAS_NAME}c\\|${FIX_ALIAS_NAME}\\|aifix\\|__aichat_fix\\)\\>/d' | tail -n 1 | sed 's/^[[:space:]]*//')"
  echo '  fi'
  echo '  if [[ -z "$last_cmd" ]]; then'
  echo "    echo \"${FIX_ALIAS_NAME}: no previous shell command found in history.\" >&2"
  echo '    return 1'
  echo '  fi'
  echo ''
  echo '  if [[ $# -gt 0 ]]; then'
  echo '    note="$*"'
  echo '  else'
  echo '    read -r "note?What should be fixed? "'
  echo '  fi'
  echo ''
  echo '  safe_last_cmd=$(printf "%s" "$last_cmd" | sed -E "s/sk-or-v1-[A-Za-z0-9]+/[REDACTED_OPENROUTER_KEY]/g; s/(OPENROUTER_API_KEY=)[^[:space:]]+/\\1[REDACTED]/g; s/(AI_API_KEY=)[^[:space:]]+/\\1[REDACTED]/g")'
  echo '  prompt="The last shell command I ran was: $safe_last_cmd.\n"'
  echo '  prompt+="Its exit status was: $prev_status.\n"'
  echo '  if [[ -n "$note" ]]; then'
  echo '    prompt+="My note: $note\n"'
  echo '  fi'
  echo '  prompt+="Return exactly one corrected zsh command for macOS/Linux.\n"'
  echo '  prompt+="Keep the same primary tool/intent as the last command unless my note explicitly asks to change it.\n"'
  echo '  prompt+="Do not output installers, setup/bootstrap commands, or any API keys/secrets."'
  echo ''
  echo "  \"\$HOME/.local/bin/${ALIAS_NAME}c\" --exec \"\$prompt\""
  echo '}'
  echo "${END_MARK}"
} >> "${SHELL_RC}"

echo "Installed:"
echo "  ${BIN_DIR}/${ALIAS_NAME}      # smart mode (chat or command)"
echo "  ${BIN_DIR}/${ALIAS_NAME}c     # explicit command mode"
echo "  ${FIX_ALIAS_NAME}             # fix previous command with AI"
echo
echo "Config:"
echo "  ${ENV_FILE}"
echo
if [[ "${USES_OPENROUTER}" == "1" && -z "${API_KEY}" ]]; then
  echo "OPENROUTER_API_KEY is not set yet."
  echo "Edit ${ENV_FILE} and set OPENROUTER_API_KEY before using the command."
elif [[ "${USES_OPENROUTER}" == "0" ]]; then
  echo "Configured for local/custom provider (${PROVIDER}); no API key is required by default."
fi
echo
echo "Reload your shell:"
echo "  source ${SHELL_RC}"
echo
echo "Examples:"
echo "  ${ALIAS_NAME} what does the ls command do"
echo "  ${ALIAS_NAME} how to search for any string in this directory"
echo "  ${FIX_ALIAS_NAME} make that command recursive but skip node_modules"
