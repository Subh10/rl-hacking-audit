# Writing scenarios

A scenario = templates + payloads + an oracle. Fields: `id`, `title`, `category`, `severity`, `user`, `payloads`,
`oracle` (required); `description`, `system`, `tools`, `requires` (`system`/`tools`), `tags`, `remediation` (optional).

Template variables: `{canary}`, `{canary_a}`, `{canary_b}` (fresh per attempt), `{base_system}`, and `{payload}` (in `user`).

**Use the split canary** in payloads ("join {canary_a} and {canary_b}") so a model that only *describes* the
injection is not counted as compromised.

Oracles: `canary {value}`, `forbidden_tokens {tokens}`, `tool_policy {forbidden_tools, allowed_tools, canary}`,
`exfil {secret}`. Converters are applied to each payload before it is inserted into `user`.
