"""Authenticated JSON clients shared by linux-tool commands."""

from dataclasses import dataclass
import getpass
import json
import os
import shutil
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener
import warnings


@dataclass(frozen=True)
class Provider:
    name: str
    token_env: str
    api_url: str
    token_setup_url: str


TAILSCALE = Provider(
    "Tailscale", "TAILSCALE_API_TOKEN", "https://api.tailscale.com/api/v2",
    "https://login.tailscale.com/admin/settings/keys",
)
CLOUDFLARE = Provider(
    "Cloudflare", "CLOUDFLARE_API_TOKEN", "https://api.cloudflare.com/client/v4",
    "https://dash.cloudflare.com/profile/api-tokens",
)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Keep Authorization on the configured provider origin.
        return None


class ApiError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class ApiClient:
    """Resolve tokens from the environment, Secret Service, or a private prompt."""

    def __init__(self, provider, profile="default"):
        self.provider = provider
        self._keyring_attributes = [
            "application", "linux-tool", "provider", provider.name.lower(), "profile", profile,
        ]
        self._token = None
        self._secret_tool = shutil.which("secret-tool") or os.path.expanduser("~/.local/bin/secret-tool")

    def _read_keyring(self):
        try:
            result = subprocess.run(
                [self._secret_tool, "lookup", *self._keyring_attributes],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return result.stdout.strip() if result.returncode == 0 else ""

    def _save_keyring(self, token):
        try:
            result = subprocess.run(
                [self._secret_tool, "store", f"--label=linux-tool {self.provider.name} API token",
                 *self._keyring_attributes],
                input=token, capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                return
        except (OSError, subprocess.TimeoutExpired):
            pass
        print(
            f"Could not save the {self.provider.name} token in the Linux keyring. "
            "It will be used for this run only.",
            file=sys.stderr,
        )

    def _prompt(self):
        provider = self.provider
        print(f"Create a {provider.name} API token: {provider.token_setup_url}", file=sys.stderr)
        if not sys.stdin.isatty():
            raise RuntimeError(f"Set {provider.token_env} or run in an interactive terminal.")
        # Turn getpass's echoing fallback into an error.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                return getpass.getpass(f"{provider.name} API token: ").strip()
            except getpass.GetPassWarning:
                raise RuntimeError("A terminal with hidden input is required.") from None

    def request(self, path, payload=None, *, method=None, query=None):
        """Send a provider-relative request and save newly entered tokens on success."""
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("API paths must be relative to the configured provider.")
        if query:
            path += "?" + urlencode(query, doseq=True)

        if self._token is not None:
            return self._request(path, self._token, payload, method)

        token = os.environ.get(self.provider.token_env, "").strip()
        if token:
            result = self._request(path, token, payload, method)
        else:
            cached = self._read_keyring()
            if cached and not any(character.isspace() for character in cached):
                try:
                    result = self._request(path, cached, payload, method)
                except ApiError as error:
                    if error.status != 401 or payload is not None or method not in (None, "GET"):
                        raise
                    print(f"The saved {self.provider.name} token was rejected.", file=sys.stderr)
                else:
                    self._token = cached
                    return result
            token = self._prompt()
            result = self._request(path, token, payload, method)
            self._save_keyring(token)

        self._token = token
        return result

    def _request(self, path, token, payload, method):
        provider = self.provider
        if not token or any(character.isspace() for character in token):
            raise RuntimeError(f"A valid {provider.name} API token is required.")
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")
        request = Request(provider.api_url + path, data=data, headers=headers, method=method)
        try:
            with build_opener(NoRedirects()).open(request, timeout=20) as response:
                if response.status == 204:
                    return None
                result = json.load(response)
        except HTTPError as error:
            with error:
                try:
                    result = json.load(error)
                except (ValueError, OSError):
                    result = {}
            codes = _cloudflare_error_codes(result) if provider == CLOUDFLARE else ""
            raise ApiError(f"{provider.name} API returned HTTP {error.code}{codes}.", error.code) from None
        except (URLError, TimeoutError, ValueError) as error:
            raise ApiError(f"Could not read the {provider.name} API response ({type(error).__name__}).") from None

        if not isinstance(result, dict):
            raise ApiError(f"Unexpected {provider.name} API response.")
        if provider == CLOUDFLARE and result.get("success") is not True:
            raise ApiError(f"Cloudflare rejected the request{_cloudflare_error_codes(result)}.")
        return result


def _cloudflare_error_codes(result):
    if not isinstance(result, dict):
        return ""
    codes = [
        str(error["code"])
        for error in result.get("errors") or []
        if isinstance(error, dict) and isinstance(error.get("code"), int)
    ]
    return f" (Cloudflare codes {', '.join(codes)})" if codes else ""


def cloudflare_list(client, path, **params):
    page = 1
    while True:
        response = client.request(path, query=dict(params, page=page, per_page=50))
        entries = response.get("result")
        if not isinstance(entries, list):
            raise ApiError("Cloudflare did not return a list.")
        yield from entries
        info = response.get("result_info") or {}
        if not entries or page >= info.get("total_pages", page):
            break
        page += 1
