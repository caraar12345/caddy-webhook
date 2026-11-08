"""The few GitHub API calls Wall Dash deploys need, always against
api.github.com (never a URL from a webhook payload)."""

from __future__ import annotations

import zipfile

import httpx

API = "https://api.github.com"
HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


class GitHub:
    def __init__(self, token: str, repo: str, transport: httpx.BaseTransport | None = None):
        self.repo = repo
        self._client = httpx.Client(
            base_url=API,
            headers={**HEADERS, "Authorization": f"Bearer {token}"},
            # httpx drops Authorization when a download redirects to another host
            follow_redirects=True,
            timeout=60,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def _get(self, path: str, **params) -> dict | list:
        response = self._client.get(f"/repos/{self.repo}{path}", params=params or None)
        response.raise_for_status()
        return response.json()

    def run(self, run_id: int) -> dict:
        return self._get(f"/actions/runs/{run_id}")

    def pull(self, number: int) -> dict:
        return self._get(f"/pulls/{number}")

    def open_pull_numbers(self) -> set[int]:
        numbers: set[int] = set()
        page = 1
        while True:
            pulls = self._get("/pulls", state="open", per_page=100, page=page)
            numbers.update(p["number"] for p in pulls)
            if len(pulls) < 100:
                return numbers
            page += 1

    def pull_for_branch(self, owner: str, branch: str) -> int | None:
        pulls = self._get("/pulls", state="open", head=f"{owner}:{branch}")
        return pulls[0]["number"] if pulls else None

    def download_artifact(self, run_id: int, name: str, dest_zip: str) -> zipfile.ZipFile:
        """Download the run's newest unexpired artifact called name."""
        listing = self._get(f"/actions/runs/{run_id}/artifacts", name=name, per_page=100)
        artifacts = [
            a for a in listing.get("artifacts", []) if a.get("name") == name and not a.get("expired")
        ]
        if not artifacts:
            raise RuntimeError(f"run {run_id} has no unexpired '{name}' artifact")
        newest = max(artifacts, key=lambda a: a.get("created_at") or "")
        with self._client.stream(
            "GET", f"/repos/{self.repo}/actions/artifacts/{newest['id']}/zip"
        ) as response:
            response.raise_for_status()
            with open(dest_zip, "wb") as f:
                for chunk in response.iter_bytes():
                    f.write(chunk)
        return zipfile.ZipFile(dest_zip)
