# caddy-webhook

A very opinionated tool designed for me to get back into writing FastAPI programs, but also allow for my Caddyfile config to be updated automatically.

## Endpoints

Both check GitHub's `X-Hub-Signature-256` against `github_webhook_secret`.

### `POST /webhook`: infra-caddy

A push to the Caddy repo pulls it into `git_repo_path` and reloads Caddy.

### `POST /webhook/wall-dash`: Wall Dash deploys

[home-assistant-wall-dash](https://github.com/caraar12345/home-assistant-wall-dash)
builds on every push to `main` (`.github/workflows/deploy.yaml`) and uploads a
`wall-dash` artifact. When the run finishes, GitHub's `workflow_run` webhook lands
here; the add-on downloads the artifact and writes it into Home Assistant's config:

- `www/` to `wall_dash_www_dir` (`/homeassistant/www/wall-dash`, served at
  `/local/wall-dash/`). Files are overwritten in place, entry points last; hashed
  assets no build has shipped for 31 days are pruned.
- `custom_components/wall_dash` to `wall_dash_integration_dir`, swapped in whole
  and only when it changed. HA needs a restart for that, so a persistent
  notification says so.

Every deploy fires `wall_dash_deployed` (`commit`, `branch`, `devices`,
`integration_changed`) on HA's event bus, and posts to Discord. Running the
workflow by hand on a branch deploys that branch; re-running an older run rolls
back to it.

Setup:

1. A fine-grained GitHub token with read-only **Actions** access to
   home-assistant-wall-dash, in the `wall_dash_github_token` option. Artifacts
   can't be downloaded without one, even from a public repo.
2. A webhook on home-assistant-wall-dash (Settings → Webhooks): payload URL
   `https://<this add-on>/webhook/wall-dash`, content type `application/json`,
   the same secret as `github_webhook_secret`, and only the **Workflow runs**
   event.
