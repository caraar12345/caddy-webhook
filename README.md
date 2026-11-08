# caddy-webhook

A very opinionated tool designed for me to get back into writing FastAPI programs, but also allow for my Caddyfile config to be updated automatically. It's a Home Assistant add-on that takes GitHub webhooks at `hooks.adhd.energy` and deploys two things:

- **infra-caddy**: the Caddyfile, at `POST /webhook`
- **Wall Dash**: the wall panel dashboard and its integration, at `POST /webhook/wall-dash`

Both endpoints check GitHub's `X-Hub-Signature-256` HMAC before reading anything. Each has its own secret if `wall_dash_webhook_secret` is set. Caddy only lets GitHub's webhook ranges reach the add-on (infra-caddy's `github_hooks_and_internal_only`, regenerated daily from `api.github.com/meta`). FastAPI's docs and OpenAPI endpoints are off. Errors go to Discord and logfire, not back in HTTP responses.

## `POST /webhook`: infra-caddy

On a signed `push` to `git_repo_branch` of the repo in `git_repo_url`:

1. The webhook is only a nudge. The add-on fetches the branch over SSH (strict host-key checking against `git_ssh_known_hosts_file`, the key in `git_ssh_key_file`). The commit it deploys is the branch's head, never one named in the payload, so a replayed or forged delivery can't choose an old commit.
2. It deploys **fast-forwards only**. If the branch no longer contains the deployed commit (a force-push, or local commits in the checkout), it refuses, posts to Discord and returns 409. Fix the checkout by hand.
3. It writes `snippets/generated/config_version.caddy` and runs `caddy reload` in the Caddy container.
4. If Caddy rejects the config, Caddy keeps running the old one. The add-on also resets the checkout to the old commit, so a later Caddy restart doesn't pick up the config that failed. The next push that fixes it still fast-forwards.

Other events, branches and repos get a 200 "Ignored". Deploys run one at a time.

## `POST /webhook/wall-dash`: Wall Dash

[home-assistant-wall-dash](https://github.com/caraar12345/home-assistant-wall-dash)'s `.github/workflows/deploy.yaml` builds every push to `main` and every pull request. It signs the tarball with [Sigstore](https://www.sigstore.dev/), keylessly, and uploads one artifact, `wall-dash`: `wall-dash.tar.gz` plus `wall-dash.tar.gz.sigstore.json`.

When a run finishes, GitHub's `workflow_run` webhook arrives here. Only the run ID is used. In the background, the add-on:

1. Fetches the run from `api.github.com` and decides from GitHub's answer:
   - a successful `push` or `workflow_dispatch` on `wall_dash_branch` is **production**
   - a successful `pull_request` from the repo itself (not a fork), whose PR is still open, is a **preview**
   - anything else is ignored
2. Downloads the run's artifact with `wall_dash_github_token`.
3. **Verifies provenance before unpacking anything**, against Sigstore's public-good trust root. The signing certificate must be:
   - from GitHub Actions,
   - for `deploy.yaml` at the run's ref (`refs/heads/main`, or `refs/pull/<n>/merge`) in this repo,
   - from this run (any attempt).

   Production builds must also be for the run's commit. A PR build checks out GitHub's merge commit, so the run ID binds it instead. A failure writes nothing and posts to Discord.
4. Deploys:
   - **Production**: `www/` to `wall_dash_www_dir` (`/homeassistant/www/wall-dash`, served at `/local/wall-dash/`), overwritten in place with entry points last. Hashed assets no build has shipped for 31 days are pruned. `custom_components/wall_dash` goes to `wall_dash_integration_dir`, swapped in whole and only when it changed; HA needs a restart for that, so a persistent notification says so. Fires `wall_dash_deployed` (`commit`, `devices`, `integration_changed`) on HA's event bus.
   - **Preview**: `www/` to `wall_dash_preview_dir/<n>` (`/share/wall-dash/pr/<n>`), swapped in whole. Caddy serves it, internal only, at `wall_dash_preview_url/<n>/<device>/` (`https://hass-new.adhd.energy/wall-dash/pr/...`). The emoji are a symlink to one shared copy. The integration is never deployed from a PR; Discord says if the PR changes it.
5. Keeps the bundle and a line per deploy in `/data/wall-dash/`, and posts to Discord with links to the run and its Rekor entry.

A `pull_request` `closed` event removes that PR's preview. Every deploy also removes previews of PRs that aren't open any more. Re-running an older `main` run redeploys it, which is how to roll back.

### Setup

1. A fine-grained GitHub token for home-assistant-wall-dash only, with read-only **Actions** and **Pull requests**, in `wall_dash_github_token`. Artifacts can't be downloaded without one, even from a public repo.
2. A webhook on home-assistant-wall-dash (Settings → Webhooks):
   - payload URL `https://hooks.adhd.energy/webhook/wall-dash`
   - content type `application/json`
   - the secret in `wall_dash_webhook_secret` (or `github_webhook_secret` if that's unset)
   - events: **Workflow runs** and **Pull requests**
3. infra-caddy's `/wall-dash/pr/*` route on `hass-new.adhd.energy`.

## Development

```sh
cd caddy-webhook
uv sync
uv run pytest
```
