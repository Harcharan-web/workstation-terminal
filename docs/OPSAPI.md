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

A launch link never signs anyone in, never carries a command, and works once.

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
`v` (1), `id`, `iat`, `exp`, `task`, `num`, `title`, `path`, `agent`, `prompt`, `by`, `return`, `ws`.
The OpsAPI side is documented in `docs/AI_RUNNER_WEB_TERMINAL.md` in the OpsAPI repository.

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
