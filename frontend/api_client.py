"""Thin HTTP client used by the Streamlit UI. The UI holds no authority of its own: every action is a
call to the authenticated API, which enforces roles, approver membership and the healing rules."""

from typing import Any

import httpx


class ApiError(RuntimeError):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


class TriageApi:
    def __init__(self, base_url: str, *, token: str | None = None, demo_principal: str | None = None,
                 http: httpx.Client | None = None) -> None:
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif demo_principal:
            headers["X-Demo-Principal"] = demo_principal
        self._http = http or httpx.Client(base_url=base_url, timeout=60)
        self._headers = headers

    def _check(self, response: httpx.Response) -> Any:
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            raise ApiError(response.status_code, str(detail))
        return response.json()

    def get(self, path: str, **params: Any) -> Any:
        return self._check(self._http.get(path, headers=self._headers, params=params or None))

    def post(self, path: str, body: Any) -> Any:
        return self._check(self._http.post(path, headers=self._headers, json=body))

    def health(self) -> dict[str, Any]:
        return self._check(self._http.get("/health"))
