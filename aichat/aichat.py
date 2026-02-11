#!/usr/bin/env python3

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from urllib.parse import urlparse

import requests


DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "google/gemini-2.5-flash-lite"
DEFAULT_TIMEOUT = 60
DEFAULT_RETRY_COUNT = 2
DEFAULT_RETRY_BACKOFF = 1.0
DEFAULT_COMMAND_REPAIR_ATTEMPTS = 2
DEFAULT_LAST_COMMAND_FILE = "~/.config/ai-chat-shell/last_command"
DEFAULT_CHAT_SYSTEM_PROMPT = (
    "You are a helpful assistant for terminal users. Be concise and practical."
)
DEFAULT_COMMAND_SYSTEM_PROMPT = (
    "Return exactly one shell command for macOS/Linux zsh. "
    "If the task has multiple steps, combine them into a single one-liner command. "
    "No markdown, no explanations, no code fences."
)
DEFAULT_CLASSIFIER_SYSTEM_PROMPT = (
    "Classify the user request for a terminal assistant. "
    "Return exactly one token: COMMAND or CHAT. "
    "Return COMMAND only when the user is asking for a shell command they could run."
)
TRUSTED_AUTH_HOSTS = {"openrouter.ai", "localhost", "127.0.0.1", "::1"}
RISK_LEVEL_ORDER = {"low": 1, "medium": 2, "high": 3}
RISK_PATTERNS = (
    (r"\bsudo\b", "needs-sudo", "medium"),
    (r"\brm\s+-rf\b", "recursive-delete", "high"),
    (r"\brm\b[^\n]*\*", "wildcard-delete", "high"),
    (r"\bmkfs(\.\w+)?\b", "filesystem-format", "high"),
    (r"\bdd\b[^\n]*\bof=/dev/", "raw-disk-write", "high"),
    (r"\b(chmod|chown)\b[^\n]*/(etc|usr|bin|sbin)\b", "system-permission-change", "high"),
    (r"\b(curl|wget)\b[^\n]*\|\s*(sh|bash|zsh)\b", "remote-script-pipe", "high"),
    (r"(?:^|[;&|])\s*:\(\)\s*\{", "fork-bomb-pattern", "high"),
    (r">\s*/(etc|usr|bin|sbin|var)\b", "system-file-write", "high"),
)
SECRET_PATTERNS = (r"sk-or-v1-[A-Za-z0-9]+",)
SECRET_ASSIGNMENT_PATTERNS = (
    r"\bOPENROUTER_API_KEY\s*=\s*['\"]?([A-Za-z0-9._-]{12,})",
    r"\bAI_API_KEY\s*=\s*['\"]?([A-Za-z0-9._-]{12,})",
)
SECRET_PLACEHOLDER_MARKERS = (
    "your_",
    "your-",
    "example",
    "placeholder",
    "redacted",
    "replace",
    "changeme",
    "dummy",
    "sample",
    "test",
)


def env_float(name):
    value = os.getenv(name)
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def env_int(name):
    value = os.getenv(name)
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def parse_args():
    fallback_default = os.getenv("AI_FALLBACK_MODEL", "").strip()
    parser = argparse.ArgumentParser(
        description=(
            "OpenRouter chat shell. Provide a prompt for one-shot mode, "
            "or run without a prompt to start interactive mode."
        )
    )
    parser.add_argument("prompt", nargs="*", help="Prompt text.")
    parser.add_argument(
        "-m",
        "--model",
        default=os.getenv("AI_MODEL", DEFAULT_MODEL),
        help=f"Model name (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("AI_BASE_URL", DEFAULT_BASE_URL),
        help=f"API base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("OPENROUTER_API_KEY") or os.getenv("AI_API_KEY"),
        help="API key. Defaults to OPENROUTER_API_KEY or AI_API_KEY.",
    )
    parser.add_argument(
        "-c",
        "--command-only",
        action="store_true",
        help="Generate commands instead of general chat answers.",
    )
    parser.add_argument(
        "--auto-command",
        action="store_true",
        help=(
            "One-shot mode only: auto-detect whether prompt should be chat or command. "
            "If command is chosen, uses command mode."
        ),
    )
    parser.add_argument(
        "--exec",
        action="store_true",
        help=(
            "In command-only mode, ask for confirmation; allow feedback to refine the "
            "command; execute when confirmed."
        ),
    )
    parser.add_argument(
        "--system-prompt",
        default=os.getenv("AI_SYSTEM_PROMPT", ""),
        help="Override system prompt.",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=env_float("AI_TEMPERATURE"),
        help="Sampling temperature.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=env_int("AI_MAX_TOKENS"),
        help="Maximum output tokens.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=env_float("AI_TIMEOUT") or DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--retry-count",
        type=int,
        default=env_int("AI_RETRY_COUNT") if env_int("AI_RETRY_COUNT") is not None else DEFAULT_RETRY_COUNT,
        help=f"Retries per model request before failing over (default: {DEFAULT_RETRY_COUNT}).",
    )
    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=env_float("AI_RETRY_BACKOFF") or DEFAULT_RETRY_BACKOFF,
        help=f"Base backoff seconds between retries (default: {DEFAULT_RETRY_BACKOFF}).",
    )
    parser.add_argument(
        "--fallback-model",
        default=fallback_default,
        help="Optional fallback model if primary model fails repeatedly.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON responses (and execution status events).",
    )
    return parser.parse_args()


def normalize_base_url(base_url):
    return base_url.rstrip("/")


def base_url_host(base_url):
    normalized = base_url if "://" in base_url else f"https://{base_url}"
    parsed = urlparse(normalized)
    return (parsed.hostname or "").lower()


def is_openrouter_host(base_url):
    host = base_url_host(base_url)
    return host == "openrouter.ai" or host.endswith(".openrouter.ai")


def is_trusted_auth_host(base_url):
    host = base_url_host(base_url)
    if not host:
        return False
    return host in TRUSTED_AUTH_HOSTS or host.endswith(".openrouter.ai")


def allow_non_openrouter_auth():
    return os.getenv("AI_ALLOW_NON_OPENROUTER_AUTH", "").strip().lower() in {"1", "true", "yes"}


def should_send_auth_header(base_url):
    if is_openrouter_host(base_url):
        return True
    if allow_non_openrouter_auth() and is_trusted_auth_host(base_url):
        return True
    return False


def requires_api_key(base_url):
    return is_openrouter_host(base_url)


def build_headers(base_url, api_key):
    headers = {"Content-Type": "application/json"}
    if api_key and should_send_auth_header(base_url):
        headers["Authorization"] = f"Bearer {api_key}"
    if is_openrouter_host(base_url):
        headers["HTTP-Referer"] = os.getenv("OPENROUTER_HTTP_REFERER", "https://localhost")
        headers["X-Title"] = os.getenv("OPENROUTER_APP_NAME", "ai-chat-shell")
    return headers


def extract_message_content(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for chunk in content:
            if isinstance(chunk, dict) and chunk.get("type") == "text":
                parts.append(chunk.get("text", ""))
        return "".join(parts).strip()
    return str(content)


def chat_completion(base_url, api_key, model, messages, temperature, max_tokens, timeout):
    endpoint = f"{normalize_base_url(base_url)}/chat/completions"
    payload = {"model": model, "messages": messages}
    if temperature is not None:
        payload["temperature"] = temperature
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens

    response = requests.post(
        endpoint,
        headers=build_headers(base_url, api_key),
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()

    choices = data.get("choices", [])
    if not choices:
        raise ValueError("No choices returned by API.")

    message = choices[0].get("message", {})
    content = extract_message_content(message.get("content", ""))
    if not content:
        raise ValueError("Model returned an empty response.")
    return content


def completion_models(primary_model, fallback_model):
    models = [primary_model]
    fallback = (fallback_model or "").strip()
    if fallback and fallback not in models:
        models.append(fallback)
    return models


def request_completion(args, model, messages, temperature=None, max_tokens=None):
    last_error = None
    for model_name in completion_models(model, args.fallback_model):
        for attempt in range(args.retry_count + 1):
            try:
                output = chat_completion(
                    base_url=args.base_url,
                    api_key=args.api_key,
                    model=model_name,
                    messages=messages,
                    temperature=args.temperature if temperature is None else temperature,
                    max_tokens=args.max_tokens if max_tokens is None else max_tokens,
                    timeout=args.timeout,
                )
                return output, model_name
            except (requests.RequestException, ValueError) as exc:
                last_error = exc
                if attempt >= args.retry_count:
                    break
                delay = max(args.retry_backoff, 0) * (2**attempt)
                if delay > 0:
                    time.sleep(delay)
    if last_error is not None:
        raise last_error
    raise ValueError("No model request was attempted.")


def strip_markdown_fences(text):
    output = text.strip()
    if output.startswith("```") and output.endswith("```"):
        lines = output.splitlines()
        if len(lines) >= 3:
            output = "\n".join(lines[1:-1]).strip()
    if output.startswith("`") and output.endswith("`") and len(output) > 2:
        output = output[1:-1].strip()
    return output


def normalize_command_output(text):
    command = strip_markdown_fences(text).strip()
    if command.startswith("$ "):
        command = command[2:].strip()
    if command.startswith("zsh$ "):
        command = command[5:].strip()
    return command


def command_primary_executable(command):
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.strip().split()

    assignment = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
    for part in parts:
        if assignment.match(part):
            continue
        if part == "env":
            continue
        return os.path.basename(part)
    return ""


def expected_primary_from_fix_prompt(messages):
    marker = "The last shell command I ran was:"
    for entry in reversed(messages):
        if entry.get("role") != "user":
            continue
        content = entry.get("content", "")
        if marker not in content:
            continue
        match = re.search(r"The last shell command I ran was:\s*(.+?)(?:\\n|\n|$)", content, re.DOTALL)
        if not match:
            continue
        previous_command = match.group(1).strip()
        return command_primary_executable(previous_command)
    return ""


def is_secret_like_assignment_value(value):
    candidate = value.strip("'\"").strip()
    if len(candidate) < 20:
        return False
    lowered = candidate.lower()
    if candidate.startswith("[") and candidate.endswith("]"):
        return False
    if any(marker in lowered for marker in SECRET_PLACEHOLDER_MARKERS):
        return False
    return bool(re.search(r"[A-Za-z]", candidate) and re.search(r"\d", candidate))


def validate_command_output(command):
    issues = []
    if not command:
        issues.append("empty output")
    if "```" in command:
        issues.append("contains markdown fences")
    if "\n" in command or "\r" in command:
        issues.append("must be a single line command")
    lowered = command.lower()
    if lowered.startswith(("run ", "use ", "here is ", "this command ", "you can ")):
        issues.append("contains explanatory text")
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, command):
            issues.append("contains secret-like token")
            break
    else:
        for pattern in SECRET_ASSIGNMENT_PATTERNS:
            for match in re.finditer(pattern, command):
                if is_secret_like_assignment_value(match.group(1)):
                    issues.append("contains secret-like token")
                    break
            if "contains secret-like token" in issues:
                break
    return issues


def enforce_command_quality(args, model, messages, output):
    candidate = normalize_command_output(output)
    expected_primary = expected_primary_from_fix_prompt(messages)
    for attempt in range(DEFAULT_COMMAND_REPAIR_ATTEMPTS + 1):
        issues = validate_command_output(candidate)
        if expected_primary:
            candidate_primary = command_primary_executable(candidate)
            if candidate_primary and candidate_primary != expected_primary:
                issues.append(f"changes primary executable (expected {expected_primary})")
        if not issues:
            return candidate
        if attempt >= DEFAULT_COMMAND_REPAIR_ATTEMPTS:
            raise ValueError(f"Model returned invalid command output: {', '.join(issues)}.")
        repair_request = (
            "Your last response is invalid for strict command mode. "
            f"Issues: {', '.join(issues)}. "
            "Return exactly one shell command for macOS/Linux zsh on a single line. "
            "No markdown, no explanation, no prompt prefix."
        )
        if "contains secret-like token" in issues:
            repair_request += (
                " Do not include API keys, token-like strings, or OPENROUTER_API_KEY/AI_API_KEY "
                "assignments."
            )
        if expected_primary:
            repair_request += (
                f" Keep the primary executable as '{expected_primary}' unless the user explicitly "
                "asked to change tools."
            )
        repair_messages = messages + [
            {"role": "assistant", "content": candidate},
            {"role": "user", "content": repair_request},
        ]
        repaired, _ = request_completion(args, model, repair_messages)
        candidate = normalize_command_output(repaired)
    return candidate


def analyze_command_risk(command):
    tags = []
    level = "low"
    for pattern, tag, tag_level in RISK_PATTERNS:
        if re.search(pattern, command):
            tags.append(tag)
            if RISK_LEVEL_ORDER[tag_level] > RISK_LEVEL_ORDER[level]:
                level = tag_level
    unique_tags = sorted(set(tags))
    return {
        "is_risky": bool(unique_tags),
        "level": level if unique_tags else "low",
        "tags": unique_tags,
    }


def classify_command_exit(command, returncode):
    if returncode == 0:
        return "executed", None

    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.strip().split()

    if not parts:
        return "failed", None

    base = os.path.basename(parts[0])
    non_error_one = {"grep", "egrep", "fgrep", "rg", "ripgrep", "diff", "cmp"}
    if returncode == 1 and base in non_error_one:
        if base in {"grep", "egrep", "fgrep", "rg", "ripgrep"}:
            return "executed-no-match", "No matches found."
        if base in {"diff", "cmp"}:
            return "executed-different", "Inputs differ."

    return "failed", None


def last_command_file():
    return os.path.expanduser(os.getenv("AI_LAST_COMMAND_FILE", DEFAULT_LAST_COMMAND_FILE))


def persist_last_command(command):
    path = last_command_file()
    directory = os.path.dirname(path)
    try:
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(f"{command}\n")
    except OSError:
        return False
    return True


def emit_model_output(args, mode, output, model_used, reason):
    if args.json:
        payload = {"mode": mode, "model": model_used, "reason": reason}
        if mode == "command":
            payload["command"] = output
            payload["risk"] = analyze_command_risk(output)
        else:
            payload["response"] = output
        print(json.dumps(payload, ensure_ascii=True))
        return
    print(output)


def emit_exec_event(args, command, status, risk, exit_code=None):
    if not args.json:
        return
    payload = {
        "mode": "command_exec",
        "command": command,
        "status": status,
        "risk": risk,
    }
    if exit_code is not None:
        payload["exit_code"] = exit_code
    print(json.dumps(payload, ensure_ascii=True))


def confirm_risky_execution(command, risk):
    if not risk["is_risky"]:
        return True
    tags = ", ".join(risk["tags"]) if risk["tags"] else "unknown-risk"
    print(f"Risk warning [{risk['level']}]: {tags}")
    confirmation = input("Type 'run' to execute anyway, or anything else to skip.\n> ").strip().lower()
    return confirmation == "run"


def prompt_from_args(args):
    arg_prompt = " ".join(args.prompt).strip()
    stdin_prompt = ""
    if not sys.stdin.isatty():
        stdin_prompt = sys.stdin.read().strip()

    if arg_prompt and stdin_prompt:
        return f"{arg_prompt}\n\n{stdin_prompt}".strip()
    return arg_prompt or stdin_prompt


def make_system_prompt(command_only, custom_prompt):
    if custom_prompt:
        return custom_prompt
    return DEFAULT_COMMAND_SYSTEM_PROMPT if command_only else DEFAULT_CHAT_SYSTEM_PROMPT


def looks_like_command_request(prompt):
    lowered = prompt.strip().lower()
    command_starters = (
        "how to ",
        "how do i ",
        "how can i ",
        "command to ",
        "give me a command",
        "show command",
        "find ",
        "search ",
        "grep ",
        "list ",
        "count ",
    )
    explanation_starters = (
        "what does ",
        "what is ",
        "explain ",
        "why ",
    )
    if lowered.startswith(explanation_starters):
        return False
    if lowered.startswith(command_starters):
        return True
    if " command " in lowered and ("how" in lowered or "run" in lowered):
        return True
    return False


def detect_command_intent(args, prompt):
    messages = [
        {"role": "system", "content": DEFAULT_CLASSIFIER_SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    try:
        decision, _ = request_completion(
            args=args,
            model=args.model,
            messages=messages,
            temperature=0,
            max_tokens=4,
        )
        decision = decision.strip().upper()
    except Exception:
        return looks_like_command_request(prompt)

    if decision.startswith("COMMAND"):
        return True
    if decision.startswith("CHAT"):
        return False
    return looks_like_command_request(prompt)


def execute_or_refine_command(args, model, messages, command):
    current_command = command
    while True:
        confirmation = input(
            f"Execute this command? [y/N or feedback]\n{current_command}\n> "
        ).strip()
        lowered = confirmation.lower()

        if lowered in {"y", "yes"}:
            risk = analyze_command_risk(current_command)
            if not confirm_risky_execution(current_command, risk):
                print("Skipped.")
                emit_exec_event(args, current_command, "skipped-risk", risk)
                return
            persist_last_command(current_command)
            completed = subprocess.run(current_command, shell=True, check=False)
            exec_status, note = classify_command_exit(current_command, completed.returncode)
            emit_exec_event(
                args,
                current_command,
                exec_status,
                risk,
                completed.returncode,
            )
            if note:
                print(note, file=sys.stderr)
            if exec_status == "failed":
                print(f"Command exited with code {completed.returncode}.", file=sys.stderr)
            return

        if not confirmation or lowered in {"n", "no", "skip", "cancel", "q", "quit"}:
            print("Skipped.")
            emit_exec_event(args, current_command, "skipped", analyze_command_risk(current_command))
            return

        refinement_request = (
            "Revise your previous command using the user's feedback. "
            "Return exactly one shell command for macOS/Linux zsh on a single line. "
            "No markdown, no explanations, no code fences.\n"
            f"Previous command: {current_command}\n"
            f"Feedback: {confirmation}"
        )
        messages.append({"role": "user", "content": refinement_request})
        try:
            revised, used_model = request_completion(args=args, model=model, messages=messages)
            current_command = enforce_command_quality(args, used_model, messages, revised)
        except requests.RequestException as exc:
            print(f"Request error: {exc}", file=sys.stderr)
            messages.pop()
            continue
        except ValueError as exc:
            print(f"Response error: {exc}", file=sys.stderr)
            messages.pop()
            continue

        messages.append({"role": "assistant", "content": current_command})
        emit_model_output(args, "command", current_command, used_model, "Refined command from feedback")


def run_one_shot(args, prompt):
    use_command_mode = args.command_only
    if args.auto_command and not args.command_only:
        use_command_mode = detect_command_intent(args, prompt)

    messages = [
        {"role": "system", "content": make_system_prompt(use_command_mode, args.system_prompt)},
        {"role": "user", "content": prompt},
    ]
    output, used_model = request_completion(args=args, model=args.model, messages=messages)
    if use_command_mode:
        output = enforce_command_quality(args, used_model, messages, output)
    emit_model_output(
        args,
        "command" if use_command_mode else "chat",
        output,
        used_model,
        "Generated response",
    )
    if use_command_mode:
        messages.append({"role": "assistant", "content": output})
    if args.exec and use_command_mode:
        execute_or_refine_command(args, used_model, messages, output)


def interactive_help():
    print("Commands:")
    print("  /help            Show this help")
    print("  /clear           Clear conversation history")
    print("  /fix [feedback]  Revise the previous assistant response")
    print("  /mode            Toggle mode between chat and command")
    print("  /mode chat       Switch to chat mode")
    print("  /mode cmd        Switch to command mode")
    print("  /model <name>    Set model for this session")
    print("  /exit            Exit")


def parse_mode_command(line, current_mode):
    parts = line.split()
    if len(parts) == 1:
        return not current_mode
    value = parts[1].lower()
    if value in {"chat", "ask", "a"}:
        return False
    if value in {"cmd", "command", "c"}:
        return True
    print("Invalid mode. Use '/mode chat' or '/mode cmd'.")
    return current_mode


def last_assistant_message(messages):
    for entry in reversed(messages):
        if entry.get("role") == "assistant":
            return entry.get("content", "")
    return ""


def run_interactive(args):
    command_only = args.command_only
    model = args.model

    def init_messages():
        return [
            {
                "role": "system",
                "content": make_system_prompt(command_only, args.system_prompt),
            }
        ]

    messages = init_messages()
    print(f"AI chat shell started. model={model} mode={'cmd' if command_only else 'chat'}")
    print("Type /help for commands.")

    while True:
        prompt_label = "cmd> " if command_only else "chat> "
        try:
            user_input = input(prompt_label).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not user_input:
            continue
        if user_input in {"/exit", "exit", "quit"}:
            break
        if user_input == "/help":
            interactive_help()
            continue
        if user_input == "/clear":
            messages = init_messages()
            print("Conversation cleared.")
            continue
        if user_input.startswith("/mode"):
            new_mode = parse_mode_command(user_input, command_only)
            if new_mode != command_only:
                command_only = new_mode
                messages = init_messages()
                print(f"Mode set to {'cmd' if command_only else 'chat'}. Conversation reset.")
            continue
        if user_input.startswith("/model "):
            model = user_input.split(" ", 1)[1].strip()
            if not model:
                print("Model cannot be empty.")
                continue
            print(f"Model set to {model}.")
            continue
        if user_input.startswith("/fix"):
            previous = last_assistant_message(messages)
            if not previous:
                print("No previous assistant response to revise.")
                continue
            feedback = user_input[4:].strip()
            if command_only:
                fix_request = (
                    "Revise your previous shell command response. "
                    "Return exactly one shell command for macOS/Linux zsh on a single line. "
                    "No markdown, no explanation.\n"
                    f"Previous response: {previous}\n"
                    f"Feedback: {feedback or 'Make it more accurate and complete.'}"
                )
            else:
                fix_request = (
                    "Revise your previous answer according to the user's feedback.\n"
                    f"Previous response: {previous}\n"
                    f"Feedback: {feedback or 'Improve clarity and correctness.'}"
                )
            messages.append({"role": "user", "content": fix_request})
            try:
                output, used_model = request_completion(args=args, model=model, messages=messages)
            except requests.RequestException as exc:
                print(f"Request error: {exc}", file=sys.stderr)
                messages.pop()
                continue
            except ValueError as exc:
                print(f"Response error: {exc}", file=sys.stderr)
                messages.pop()
                continue
            if command_only:
                try:
                    output = enforce_command_quality(args, used_model, messages, output)
                except ValueError as exc:
                    print(f"Response error: {exc}", file=sys.stderr)
                    messages.pop()
                    continue
            emit_model_output(
                args,
                "command" if command_only else "chat",
                output,
                used_model,
                "Revised previous response",
            )
            messages.append({"role": "assistant", "content": output})
            if args.exec and command_only:
                execute_or_refine_command(args, model, messages, output)
            continue

        messages.append({"role": "user", "content": user_input})
        try:
            output, used_model = request_completion(args=args, model=model, messages=messages)
        except requests.RequestException as exc:
            print(f"Request error: {exc}", file=sys.stderr)
            messages.pop()
            continue
        except ValueError as exc:
            print(f"Response error: {exc}", file=sys.stderr)
            messages.pop()
            continue

        if command_only:
            try:
                output = enforce_command_quality(args, used_model, messages, output)
            except ValueError as exc:
                print(f"Response error: {exc}", file=sys.stderr)
                messages.pop()
                continue
        emit_model_output(
            args,
            "command" if command_only else "chat",
            output,
            used_model,
            "Generated response",
        )
        messages.append({"role": "assistant", "content": output})
        if args.exec and command_only:
            execute_or_refine_command(args, model, messages, output)


def main():
    args = parse_args()
    prompt = prompt_from_args(args)

    if args.retry_count < 0:
        print("--retry-count must be >= 0.", file=sys.stderr)
        sys.exit(2)
    if args.retry_backoff < 0:
        print("--retry-backoff must be >= 0.", file=sys.stderr)
        sys.exit(2)

    if args.api_key and not should_send_auth_header(args.base_url):
        print(
            "API key provided, but Authorization is disabled for this --base-url. "
            "It will only be sent to OpenRouter hosts by default. "
            "Set AI_ALLOW_NON_OPENROUTER_AUTH=1 to opt in for trusted non-OpenRouter hosts.",
            file=sys.stderr,
        )

    if requires_api_key(args.base_url) and not args.api_key:
        print(
            "Missing API key. Set OPENROUTER_API_KEY or pass --api-key.",
            file=sys.stderr,
        )
        sys.exit(2)

    if prompt:
        try:
            run_one_shot(args, prompt)
        except requests.RequestException as exc:
            print(f"Request error: {exc}", file=sys.stderr)
            sys.exit(1)
        except ValueError as exc:
            print(f"Response error: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    run_interactive(args)


if __name__ == "__main__":
    main()
