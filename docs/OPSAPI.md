# OpsAPI task links

OpsAPI (the project management platform) can open a task straight into a terminal tab here:
**Start with AI → Work in the web terminal** on a task asks for a folder on this Mac and an agent
(Claude Code, Codex, Cursor or just a terminal). The browser then opens

```
https://<this gateway>/#launch=<ticket>
```

After the person signs in **with their SSH key as usual**, the gateway opens a tab named after the task
in that folder and starts the agent with the task as its first message. When the agent exits they are
left in an ordinary shell in the same folder. OpsAPI shows the session on the task until it ends.

A launch link never carries a command and works once. It signs nobody in, unless this gateway has
turned on [auto sign-in](#auto-sign-in-for-power-users) for that person.

## Setting it up

1. In OpsAPI: **AI Runs → Machines → Web terminals → Add**, with this gateway's public address
   (e.g. `https://dev.workstation.co.uk`). OpsAPI shows a shared secret and an `opsapi:` block **once**.
2. Paste it into this gateway's `config.yaml` and add the folders tasks may open:

   ```yaml
   local:
     allowed_roots: [~/projects]          # tabs and task links may open these folders and below

   opsapi:
     webhook_url: https://int-opsapi.workstation.co.uk/api/v2/ai-runner/public/terminal/webhook
     webhook_secret: "<from OpsAPI>"      # or SSHWEB_OPSAPI_WEBHOOK_SECRET
     agents:                              # ids must match the agents listed in OpsAPI
       - { id: claude, name: Claude Code, run: 'claude "$OPSAPI_TASK_PROMPT"' }
       - { id: codex,  name: Codex,       run: 'codex "$OPSAPI_TASK_PROMPT"' }
       - { id: cursor, name: Cursor,      run: 'cursor-agent "$OPSAPI_TASK_PROMPT"' }
       # Never stops to ask. Only acceptable because this gateway runs under its own macOS
       # account (below); leave it out to forbid unattended agents.
       - { id: claude_auto, name: "Claude Code (unattended)", run: 'claude --dangerously-skip-permissions "$OPSAPI_TASK_PROMPT"' }
     idle_timeout_secs: 14400             # task tabs: 4 h with neither input nor output
     detach_grace_secs: 14400             # task tabs keep running 4 h after the browser closes
   ```

3. `sshweb config validate`, then restart the gateway (this ends open terminals; pick a quiet moment).

`shell` (no agent) is always available. Each agent's `run` is one shell command line, run by the user's
own shell with `-i` so PATH and rc files are as in a normal terminal. The task is only available through
environment variables, so its text is never parsed as shell syntax:

| Variable | Value |
|---|---|
| `OPSAPI_TASK_PROMPT` | The prompt the person reviewed in OpsAPI (≤ 8000 characters) |
| `OPSAPI_TASK_TITLE`, `OPSAPI_TASK_NUMBER` | Task title and number |
| `OPSAPI_TASK_URL` | Link back to the task |
| `OPSAPI_TASK`, `OPSAPI_LAUNCH` | Task id and launch id |
| `OPSAPI_REPORT_URL`, `OPSAPI_REPORT_TOKEN` | Where and how the agent tells OpsAPI about its pull request (only when the link has `report`) |

Always quote it (`"$OPSAPI_TASK_PROMPT"`).

## What happens

1. The page reads `#launch=…` (a fragment, so it never reaches proxies or access logs). If the person
   isn't signed in, the sign-in screen says which task is waiting.
2. `POST /api/launch {ticket}` (login cookie and Origin, like every state-changing call). The gateway:
   - verifies the signature (HMAC-SHA256 with the shared secret, constant time), version, expiry and a
     lifetime of at most 1 hour;
   - requires `local` access for the signed-in key;
   - resolves the folder with `realpath` and requires an existing directory inside `local.allowed_roots`
     (symlinks can't escape);
   - looks the agent id up in `opsapi.agents`.
   Errors: `invalid_link`, `expired`, `not_configured`, `folder_not_found`, `folder_not_allowed`,
   `unknown_agent` (400), `forbidden` (403), `already_used` (409, another user accepted it).
3. The page opens a tab with `{"type":"open","target":{"kind":"local"},"launch":"<id>"}`. The folder,
   agent and environment come only from the accepted launch. The launch is then used up: re-posting the
   link returns the running session (a page reload re-attaches it); opening it again is refused.
4. The tab is saved with its folder, so restoring it later opens a plain shell there (no agent).
5. A banner shows the task, the agent and folder, who opened it and **Back to task** (plain text).
6. The gateway sends OpsAPI an HMAC-signed webhook when the session starts and ends:

   ```json
   {"event":"session_start","launch":"<id>","session_id":"<hex>","user":"alice","ts":1792600000,
    "exit_code":null,"reason":null}
   ```

   Header `X-Opsapi-Signature: sha256=<hex of HMAC-SHA256(secret, body)>`. Up to three tries.

Ticket format (made by OpsAPI): `base64url(json).hex(hmac_sha256(secret, base64url(json)))`, claims
`v` (1), `id`, `iat`, `exp`, `task`, `num`, `title`, `path`, `agent`, `prompt`, `by`, `return`, `ws`,
and optionally `login` `{email (≤ 254), user (UUID), stepup (unix seconds)}` and `report`
`{url (https, ≤ 512), token ([A-Za-z0-9_-]{32,128})}`. A malformed `login` or `report` makes the whole
link invalid. Claims the gateway doesn't know are ignored, so a newer OpsAPI works with an older gateway.
The OpsAPI side is documented in `docs/AI_RUNNER_WEB_TERMINAL.md` in the OpsAPI repository.

## Reporting the pull request

When the link has `report`, the shell gets `OPSAPI_REPORT_URL` and `OPSAPI_REPORT_TOKEN`. The prompt
OpsAPI writes asks the agent to call it once its pull request is open:

```sh
curl -fsS -X POST "$OPSAPI_REPORT_URL" -H "Authorization: Bearer $OPSAPI_REPORT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"pr_url":"https://github.com/o/r/pull/12"}'
```

The token can only attach pull requests and notes to its own task. The gateway never logs it.

## Auto sign-in for power users

Off by default. When it is on, OpsAPI may sign chosen people in with the task link itself, so a task
opens with one click. All of these must hold:

- OpsAPI: the terminal has auto sign-in turned on there, the person holds `ai_terminal_autologin`, and
  they confirmed an emailed code (a *step-up*) in the last 12 hours. Only then does OpsAPI add the
  `login` claim, and such a link lives 120 seconds.
- This gateway: `opsapi.autologin.enabled`, and the person's OpsAPI email is listed under `users`,
  mapped to a terminal user who has an authorized key allowing `local`:

  ```yaml
  opsapi:
    autologin:
      enabled: true
      max_stepup_age_secs: 43200      # the step-up may be at most this old
      users:                          # OpsAPI email (any case) -> terminal user
        "alice@example.com": alice
  ```

The page sees a waiting link with `login` and, if nobody is signed in, calls

```
POST /api/launch/login
{"ticket": "<the #launch= ticket>"}
```

No login cookie is needed; the Origin is checked like every state-changing call, and the call is
rate-limited per IP and counted towards the same lock-out as SSH sign-in. The gateway verifies the
ticket exactly like `/api/launch`, then requires: `login` present; `exp - iat ≤ 120`; auto sign-in on;
the email mapped; the mapped user has a key allowing `local`; `stepup ≤ iat` and
`now - stepup ≤ max_stepup_age_secs`. Each launch id signs someone in **once**.

On success the answer is the same as an SSH sign-in, with the same session cookie:

```json
{"user": "alice", "access": "local", "expires_unix": 1792643200}
```

The login is made **through that user's key** (its fingerprint and access), so revoking or narrowing the
key ends it like any other. The audit log gets `auth_success` with `via=opsapi_launch`, `opsapi_email`,
`opsapi_user` and `opsapi_launch`; refusals are `auth_failure` with the reason. Then the page posts the
same ticket to `/api/launch` as usual.

Errors (`{"error": "<code>", "message": "…"}`):

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_link` | bad signature or fields, lifetime over 120 s, or `stepup` later than `iat` |
| 400 | `expired`, `not_configured` | as for `/api/launch` |
| 403 | `autologin_off` | `opsapi.autologin.enabled` is false (or local terminals are off); not counted towards lock-out |
| 403 | `autologin_not_allowed` | the link has no `login`, the email isn't mapped, or the mapped user has no key allowing `local` |
| 403 | `stepup_stale` | the step-up is older than `max_stepup_age_secs` |
| 409 | `already_used` | this link already signed someone in |
| 429 | `rate_limited`, `locked_out` | as for SSH sign-in |
| 503 | `auth_unavailable` | the authorized keys file is missing or invalid |
| 403 | `bad_origin` | the request came from another site |

On any error the page shows the normal SSH sign-in screen with the task still waiting and a one-line
reason.

What this still protects: a stolen OpsAPI password alone isn't a shell (it also needs the emailed code
within 12 hours and an email this gateway lists); a captured link is useless after 120 seconds or once
used; only people the gateway's owner listed can be signed in, and only as the terminal user they were
mapped to. What it gives up: for those people, OpsAPI (and their mailbox) now stands in for their SSH
key. List only people you'd hand a shell on this account to.

## A separate macOS account for task terminals

Every terminal runs as the macOS account that runs `sshweb`, with that account's files, keys and tokens.
Run the gateway that employees use under **its own account**, not an owner's, so a task terminal can't
read the owner's credentials. On the Mac, as an administrator:

```sh
# 1. The account (standard, not admin). Pick a strong password; it is only for administration.
sudo sysadminctl -addUser workstation -fullName "Workstation agents" -password -
sudo mkdir -p /Users/workstation/projects /Users/workstation/.local/bin
sudo chown -R workstation:staff /Users/workstation/projects /Users/workstation/.local

# 2. The gateway binary (built from this repository) and its config, as that user.
sudo install -o workstation -m 0755 target/release/sshweb /Users/workstation/.local/bin/sshweb
sudo -iu workstation /Users/workstation/.local/bin/sshweb config init
sudo -iu workstation nano /Users/workstation/.sshweb/config.yaml   # see below
sudo -iu workstation /Users/workstation/.local/bin/sshweb config validate

# 3. Start it at boot without anyone logging in (a daemon that runs as that user).
sudo cp packaging/com.sshweb.agents.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.sshweb.agents.plist
```

Config for this instance: a different port from any other gateway (e.g. `7682`), the same
`server.trusted_proxies` and TLS approach as the existing one, `allowed_origins` = its public address,
`local.allowed_roots: [~/projects]`, and the `opsapi:` block from OpsAPI.

Then, as that user (`sudo -iu workstation`):

- sign the agents in with accounts meant for this machine. Nobody logs in to this account's desktop,
  so its login keychain stays locked: tools that keep tokens in the keychain fail there. Use token files
  instead — e.g. `claude setup-token`, then put `export CLAUDE_CODE_OAUTH_TOKEN=…` in a file only this
  account can read (`chmod 600`) and source it from `~/.zprofile`; likewise `codex login` /
  `cursor-agent login` where they offer file storage;
- give it its own GitHub access (`gh auth login --insecure-storage` with a machine account or a
  fine-grained token limited to the repositories it works on), and `git config --global user.name/user.email`;
- clone the projects into `~/projects`;
- add each person's public key: `sshweb keys add --user <name> --access local <their key>.pub`.

Finally route a public name to it (reverse proxy → `https://<mac>:7682`, see "Behind a reverse proxy"
in the README) and enter that address in OpsAPI.

People sharing this account can still see each other's work in it: separation between them is by
policy only. Separation from the owner's account is real.
