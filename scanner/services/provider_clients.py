import io
import re
import zipfile
from dataclasses import dataclass
from urllib.parse import quote, urlparse

import requests


class ProviderError(RuntimeError):
    """A safe, user-facing provider API error."""


@dataclass
class RepositoryRef:
    name: str
    full_name: str
    default_branch: str
    clone_url: str


def _github_slug(repository_url):
    path = urlparse(repository_url).path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.split("/")
    if len(parts) < 2:
        raise ProviderError("GitHub repository URL must contain owner and repository name.")
    return "/".join(parts[-2:])


def _gitlab_project(repository_url):
    path = urlparse(repository_url).path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not path:
        raise ProviderError("GitLab repository URL is invalid.")
    return path


class ProviderClient:
    def __init__(self, provider, access_token, timeout=30):
        self.provider = provider.upper()
        self.access_token = access_token
        self.timeout = timeout
        if self.provider not in {"GITHUB", "GITLAB"}:
            raise ProviderError("Unsupported repository provider.")
        if not access_token:
            raise ProviderError("The integration is not connected to a provider account.")

    @property
    def base_url(self):
        return "https://api.github.com" if self.provider == "GITHUB" else "https://gitlab.com/api/v4"

    def _request(self, method, path, **kwargs):
        headers = kwargs.pop("headers", {})
        if self.provider == "GITHUB":
            headers.setdefault("Authorization", f"Bearer {self.access_token}")
            headers.setdefault("Accept", "application/vnd.github+json")
            headers.setdefault("X-GitHub-Api-Version", "2022-11-28")
        else:
            headers.setdefault("Authorization", f"Bearer {self.access_token}")
        response = requests.request(method, self.base_url + path, headers=headers, timeout=self.timeout, **kwargs)
        if response.status_code >= 400:
            raise ProviderError(f"{self.provider} API request failed with status {response.status_code}.")
        return response

    def list_repositories(self):
        if self.provider == "GITHUB":
            data = self._request("GET", "/user/repos", params={"per_page": 100, "sort": "updated"}).json()
            return [RepositoryRef(x["name"], x["full_name"], x.get("default_branch") or "main", x["html_url"]) for x in data]
        data = self._request("GET", "/projects", params={"membership": True, "per_page": 100, "order_by": "last_activity_at"}).json()
        return [RepositoryRef(x["name"], x["path_with_namespace"], x.get("default_branch") or "main", x["web_url"]) for x in data]

    def list_branches(self, repository_url):
        if self.provider == "GITHUB":
            slug = _github_slug(repository_url)
            data = self._request("GET", f"/repos/{slug}/branches", params={"per_page": 100}).json()
            return [x["name"] for x in data]
        project = quote(_gitlab_project(repository_url), safe="")
        data = self._request("GET", f"/projects/{project}/repository/branches", params={"per_page": 100}).json()
        return [x["name"] for x in data]

    def download_repository(self, repository_url, ref):
        if self.provider == "GITHUB":
            slug = _github_slug(repository_url)
            response = self._request("GET", f"/repos/{slug}/zipball/{quote(ref, safe='')}")
        else:
            project = quote(_gitlab_project(repository_url), safe="")
            response = self._request("GET", f"/projects/{project}/repository/archive.zip", params={"sha": ref})
        return response.content


def extract_source_files(archive_bytes, max_files=500, max_file_bytes=1_000_000):
    """Extract text source files safely, ignoring binaries and path traversal."""
    allowed = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go"}
    files = []
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        for info in archive.infolist():
            if len(files) >= max_files or info.is_dir() or info.file_size > max_file_bytes:
                continue
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                continue
            if not any(name.lower().endswith(ext) for ext in allowed):
                continue
            try:
                content = archive.read(info).decode("utf-8")
            except (UnicodeDecodeError, OSError, zipfile.BadZipFile):
                continue
            files.append((name, content))
    return files
