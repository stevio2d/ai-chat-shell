# ai-chat-shell

Minimal Python CLI for chatting with OpenRouter-compatible models from your terminal.

## Current functionality

- One-shot mode (prompt from args, stdin, or both)
- Interactive REPL mode with persistent conversation context
- Chat mode and command mode (`-c`)
- Optional one-shot command intent detection (`--auto-command`)
- Optional command execution flow (`--exec`) with confirm/skip/refine loop
- OpenRouter-compatible `/chat/completions` requests
- Built-in API key host safety checks
- Structured JSON output for scripting (`--json`)
- Retry/backoff with fallback model support
- Command output validation/repair in command mode

## Install

### Option 1: Pinned + verified install (recommended)

```bash
REPO_OWNER="stevio2d"
REPO_NAME="ai-chat-shell"
REF="<full-commit-sha>"
URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REF}/install.sh"
EXPECTED_INSTALL_SHA256="<published-install-sha256>"

curl -fsSL "$URL" -o /tmp/ai-chat-install.sh
if command -v sha256sum >/dev/null 2>&1; then
  echo "${EXPECTED_INSTALL_SHA256}  /tmp/ai-chat-install.sh" | sha256sum -c -
else
  echo "${EXPECTED_INSTALL_SHA256}  /tmp/ai-chat-install.sh" | shasum -a 256 -c -
fi

export OPENROUTER_API_KEY="sk-or-..."
bash /tmp/ai-chat-install.sh --ref "$REF" --model "google/gemini-2.5-flash-lite" --alias "ai"
```

Optional: verify downloaded `aichat.py` in installer:

```bash
EXPECTED_AICHAT_SHA256="<published-aichat-py-sha256>"
bash /tmp/ai-chat-install.sh --ref "$REF" --aichat-sha256 "$EXPECTED_AICHAT_SHA256"
```

### Option 2: Quick install script

```bash
curl -fsSL https://raw.githubusercontent.com/stevio2d/ai-chat-shell/main/install.sh | bash
source ~/.zshrc
```

Default install creates:

- `ai`: smart mode (starts with `--auto-command`)
- `aic`: explicit command mode (`-c`)

Installer options:

```bash
export OPENROUTER_API_KEY="sk-or-..."
curl -fsSL https://raw.githubusercontent.com/stevio2d/ai-chat-shell/main/install.sh | bash -s -- \
  --model "google/gemini-2.5-flash-lite" \
  --alias "ai" \
  --ref "main" \
  --no-auto-command \
  --auto-exec
```

Single-line install with API key, model, and alias:

```bash
curl -fsSL https://raw.githubusercontent.com/stevio2d/ai-chat-shell/main/install.sh | OPENROUTER_API_KEY="sk-or-..." bash -s -- --model "google/gemini-2.5-flash-lite" --alias "ai"
```

Query-style input:

```bash
curl -fsSL https://raw.githubusercontent.com/stevio2d/ai-chat-shell/main/install.sh | bash -s -- \
  --from-query "model=google%2Fgemini-2.5-flash-lite&alias=ai&auto_exec=1"
```

Notes:

- Use `--from-query` when you want URL-style parameters.
- `api_key=` query parameters are intentionally ignored by the installer; use `OPENROUTER_API_KEY` instead.

### Option 3: Run from source

Requirements:

- Python 3.9+
- `requests`

```bash
pip install requests
python3 aichat/aichat.py
```

## Quick start

```bash
export OPENROUTER_API_KEY="your_key_here"
python3 aichat/aichat.py
```

One-shot:

```bash
python3 aichat/aichat.py "summarize this folder structure"
```

Command-only one-shot:

```bash
python3 aichat/aichat.py -c "find the 10 largest files here"
```

## Runtime CLI flags (`aichat.py`)

- `-m, --model`
- `--base-url`
- `--api-key`
- `-c, --command-only`
- `--auto-command`
- `--exec`
- `--system-prompt`
- `--temperature`
- `--max-tokens`
- `--timeout`
- `--retry-count`
- `--retry-backoff`
- `--fallback-model`
- `--json`

## Installer flags (`install.sh`)

- `--model`
- `--alias`
- `--base-url`
- `--ref`
- `--aichat-sha256`
- `--no-auto-command`
- `--auto-exec`
- `--from-query`

## Environment variables

- `OPENROUTER_API_KEY`: API key
- `AI_API_KEY`: fallback API key if `OPENROUTER_API_KEY` is not set
- `AI_MODEL`: default model (default: `google/gemini-2.5-flash-lite`)
- `AI_BASE_URL`: API base URL (default: `https://openrouter.ai/api/v1`)
- `AI_SYSTEM_PROMPT`: overrides default chat/command system prompts
- `AI_TEMPERATURE`: sampling temperature
- `AI_MAX_TOKENS`: max output tokens
- `AI_TIMEOUT`: request timeout seconds (default: `60`)
- `AI_RETRY_COUNT`: retries per request per model (default: `2`)
- `AI_RETRY_BACKOFF`: base backoff seconds between retries (default: `1.0`)
- `AI_FALLBACK_MODEL`: optional fallback model if primary fails
- `OPENROUTER_HTTP_REFERER`: OpenRouter `HTTP-Referer` header value
- `OPENROUTER_APP_NAME`: OpenRouter `X-Title` header value
- `AI_ALIAS`: installer default alias name
- `AI_AICHAT_SHA256`: installer expected SHA256 for `aichat.py`

Use `.env.example` as a template for local defaults.

## Interactive slash commands

- `/help`
- `/clear`
- `/fix [feedback]`
- `/mode`
- `/mode chat`
- `/mode cmd`
- `/model <name>`
- `/exit`

## Examples

Use args + stdin together:

```bash
git diff | python3 aichat/aichat.py "explain this diff briefly"
```

Auto-detect command intent (one-shot):

```bash
python3 aichat/aichat.py --auto-command "find all python files larger than 1MB"
```

Generate command and optionally execute with feedback loop:

```bash
python3 aichat/aichat.py -c --exec "list the 20 biggest files in this repo"
```

With `--exec`:

- `y` / `yes`: execute
- `n` / Enter: skip
- Any other text: regenerate command using that text as feedback
- If command risk is detected (destructive/system-level patterns), a second prompt requires typing `run`

Structured JSON output:

```bash
python3 aichat/aichat.py -c --json "find top 5 largest files"
```

Retry/backoff + fallback:

```bash
python3 aichat/aichat.py \
  --retry-count 3 \
  --retry-backoff 1.0 \
  --fallback-model "openai/gpt-4o-mini" \
  "summarize latest commits"
```

## Security notes

- Never commit API keys.
- Keep secrets in local environment variables or untracked `.env` files.
- Review generated shell commands before execution, even when using `--exec`.
- In command mode, malformed command responses are auto-repaired before display.
- Installer leaves auto-exec off by default (enable only with `--auto-exec`).
- API key auth headers are only attached for trusted hosts (`openrouter.ai`, subdomains of `openrouter.ai`, and localhost addresses).
- If `--base-url` points to OpenRouter, an API key is required.
- If `--base-url` is untrusted, the client refuses to send any provided API key.

## License

Add your preferred license in `LICENSE` (MIT, Apache-2.0, etc.).
