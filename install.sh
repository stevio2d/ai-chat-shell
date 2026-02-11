#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="stevio2d"
REPO_NAME="ai-chat-shell"
REPO_REF="${REPO_REF:-main}"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_REF}"

DEFAULT_BASE_URL="https://openrouter.ai/api/v1"
DEFAULT_MODEL="google/gemini-2.5-flash-lite"
DEFAULT_ALIAS="ai"

API_KEY="${OPENROUTER_API_KEY:-}"
MODEL="${AI_MODEL:-$DEFAULT_MODEL}"
BASE_URL="${AI_BASE_URL:-$DEFAULT_BASE_URL}"
ALIAS_NAME="${AI_ALIAS:-$DEFAULT_ALIAS}"

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
  install.sh [--model MODEL] [--alias NAME] [--base-url URL] [--ref REF] [--aichat-sha256 HEX]
             [--no-auto-command] [--auto-exec] [--from-query "model=...&alias=..."]

Examples:
  export OPENROUTER_API_KEY="sk-or-..."
  curl -fsSL https://raw.githubusercontent.com/stevio2d/ai-chat-shell/main/install.sh | bash -s -- \
    --model "google/gemini-2.5-flash-lite" --alias "ai"

  curl -fsSL https://raw.githubusercontent.com/stevio2d/ai-chat-shell/main/install.sh | bash -s -- \
    --from-query "model=google%2Fgemini-2.5-flash-lite&alias=ai&auto_exec=1"
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
      model) MODEL="${value}" ;;
      alias) ALIAS_NAME="${value}" ;;
      base_url) BASE_URL="${value}" ;;
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
      shift 2
      ;;
    --alias)
      ALIAS_NAME="${2:-}"
      shift 2
      ;;
    --base-url)
      BASE_URL="${2:-}"
      shift 2
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

if [[ ! "${ALIAS_NAME}" =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ ]]; then
  echo "Invalid alias name: ${ALIAS_NAME}" >&2
  exit 1
fi

RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_REF}"

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
  printf 'export OPENROUTER_HTTP_REFERER=%q\n' "https://localhost"
  printf 'export OPENROUTER_APP_NAME=%q\n' "ai-chat-shell"
  if [[ -n "${API_KEY}" ]]; then
    printf 'export OPENROUTER_API_KEY=%q\n' "${API_KEY}"
  else
    echo '# export OPENROUTER_API_KEY="sk-or-..."'
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
  echo 'unset -f aifix 2>/dev/null || true'
  echo "alias ${ALIAS_NAME}=\"\$HOME/.local/bin/${ALIAS_NAME}\""
  echo "alias ${ALIAS_NAME}c=\"\$HOME/.local/bin/${ALIAS_NAME}c\""
  echo 'aifix() {'
  echo '  local prev_status=$?'
  echo '  local last_cmd'
  echo '  local note'
  echo '  local prompt'
  echo ''
  echo "  last_cmd=\$(fc -ln -20 2>/dev/null | sed '/^[[:space:]]*$/d' | sed '/^[[:space:]]*\\(${ALIAS_NAME}\\|${ALIAS_NAME}c\\|aifix\\)\\>/d' | tail -n 1 | sed 's/^[[:space:]]*//')"
  echo '  if [[ -z "$last_cmd" ]]; then'
  echo '    echo "aifix: no previous shell command found in history." >&2'
  echo '    return 1'
  echo '  fi'
  echo ''
  echo '  if [[ $# -gt 0 ]]; then'
  echo '    note="$*"'
  echo '  else'
  echo '    read -r "note?What should be fixed? "'
  echo '  fi'
  echo ''
  echo '  prompt="The last shell command I ran was: $last_cmd.\n"'
  echo '  prompt+="Its exit status was: $prev_status.\n"'
  echo '  if [[ -n "$note" ]]; then'
  echo '    prompt+="My note: $note\n"'
  echo '  fi'
  echo '  prompt+="Return exactly one corrected zsh command for macOS/Linux."'
  echo ''
  echo "  \"\$HOME/.local/bin/${ALIAS_NAME}c\" --exec \"\$prompt\""
  echo '}'
  echo "${END_MARK}"
} >> "${SHELL_RC}"

echo "Installed:"
echo "  ${BIN_DIR}/${ALIAS_NAME}      # smart mode (chat or command)"
echo "  ${BIN_DIR}/${ALIAS_NAME}c     # explicit command mode"
echo
echo "Config:"
echo "  ${ENV_FILE}"
echo
if [[ -z "${API_KEY}" ]]; then
  echo "OPENROUTER_API_KEY is not set yet."
  echo "Edit ${ENV_FILE} and set OPENROUTER_API_KEY before using the command."
fi
echo
echo "Reload your shell:"
echo "  source ${SHELL_RC}"
echo
echo "Examples:"
echo "  ${ALIAS_NAME} what does the ls command do"
echo "  ${ALIAS_NAME} how to search for any string in this directory"
echo "  aifix make that command recursive but skip node_modules"
