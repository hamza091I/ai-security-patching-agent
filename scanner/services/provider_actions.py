import base64
import json
from urllib.parse import quote

from .provider_clients import ProviderClient, ProviderError, _github_slug, _gitlab_project


class ProviderActions:
    """Write operations used after a scan completes.

    The methods are deliberately provider-specific behind one small adapter so
    the worker can publish results without exposing provider tokens elsewhere.
    """

    def __init__(self, client):
        self.client = client

    def _request(self, method, path, **kwargs):
        return self.client._request(method, path, **kwargs)

    def upload_sarif(self, repository_url, commit_sha, ref, sarif_document, tool_name="AI Security Patching Agent"):
        encoded = base64.b64encode(json.dumps(sarif_document).encode("utf-8")).decode("ascii")
        if self.client.provider == "GITHUB":
            slug = _github_slug(repository_url)
            response = self._request("POST", f"/repos/{slug}/code-scanning/sarifs", json={
                "commit_sha": commit_sha,
                "ref": ref,
                "sarif": encoded,
                "tool_name": tool_name,
            })
            return {"provider": "GITHUB", "url": response.json().get("url")}
        # GitLab consumes security reports through CI artifacts. We expose a
        # safe, explicit response instead of pretending the GitHub endpoint
        # exists on GitLab.
        return {"provider": "GITLAB", "uploaded": False, "next_step": "Publish SARIF as a GitLab CI security artifact."}

    def comment(self, repository_url, number, body):
        if not body.strip():
            raise ProviderError("Comment body cannot be empty.")
        if self.client.provider == "GITHUB":
            slug = _github_slug(repository_url)
            response = self._request("POST", f"/repos/{slug}/issues/{int(number)}/comments", json={"body": body})
        else:
            project = quote(_gitlab_project(repository_url), safe="")
            response = self._request("POST", f"/projects/{project}/merge_requests/{int(number)}/notes", json={"body": body})
        return response.json()

    def comment_on_commit(self, repository_url, commit_sha, body):
        """Comment on a commit when a push has no open pull request."""
        if not body.strip():
            raise ProviderError("Comment body cannot be empty.")
        if not commit_sha:
            raise ProviderError("A commit SHA is required to comment on a commit.")
        if self.client.provider == "GITHUB":
            slug = _github_slug(repository_url)
            response = self._request("POST", f"/repos/{slug}/commits/{commit_sha}/comments", json={"body": body})
        else:
            project = quote(_gitlab_project(repository_url), safe="")
            response = self._request("POST", f"/projects/{project}/repository/commits/{commit_sha}/comments", json={"note": body})
        return response.json()

    def set_security_status(self, repository_url, commit_sha, ref, passed, description, target_url=""):
        state = "success" if passed else "failure"
        payload = {"state": state, "context": "ai-security-patching-agent/security", "description": description[:140], "target_url": target_url or ""}
        if self.client.provider == "GITHUB":
            slug = _github_slug(repository_url)
            response = self._request("POST", f"/repos/{slug}/statuses/{commit_sha}", json=payload)
        else:
            project = quote(_gitlab_project(repository_url), safe="")
            response = self._request("POST", f"/projects/{project}/statuses/{commit_sha}", json={"state": state, "name": payload["context"], "ref": ref, "description": description[:140]})
        return {"provider": self.client.provider, "state": state, "response": response.json()}
