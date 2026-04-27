from collections.abc import Iterator, Mapping, MutableMapping
from typing import Any, cast

from django.http import HttpRequest, HttpResponse


class DjangoGuardRequest:
    def __init__(self, request: HttpRequest) -> None:
        self._request = request

    @property
    def url_path(self) -> str:
        result: str = self._request.path
        return result

    @property
    def url_scheme(self) -> str:
        result: str = self._request.scheme or ""
        return result

    @property
    def url_full(self) -> str:
        result: str = self._request.build_absolute_uri()
        return result

    def url_replace_scheme(self, scheme: str) -> str:
        url: str = self._request.build_absolute_uri()
        if url.startswith("http://"):
            return scheme + "://" + url[7:]
        if url.startswith("https://"):
            return scheme + "://" + url[8:]
        return url

    @property
    def method(self) -> str:
        result: str = self._request.method or ""
        return result

    @property
    def client_host(self) -> str | None:
        result: str | None = self._request.META.get("REMOTE_ADDR")
        return result

    @property
    def headers(self) -> Mapping[str, str]:
        return DjangoHeadersMapping(self._request.META)

    @property
    def query_params(self) -> Mapping[str, str]:
        result: Mapping[str, str] = self._request.GET
        return result

    def body(self) -> bytes:
        result: bytes = self._request.body
        return result

    @property
    def state(self) -> Any:
        return self._request

    @property
    def scope(self) -> dict[str, Any]:
        return {"META": self._request.META}


class DjangoHeadersMapping(Mapping[str, str]):
    def __init__(self, meta: dict[str, Any]) -> None:
        self._headers: dict[str, str] = {}
        for key, value in meta.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].replace("_", "-").title()
                self._headers[header_name] = str(value)
            elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                header_name = key.replace("_", "-").title()
                self._headers[header_name] = str(value)

    def __getitem__(self, key: str) -> str:
        return self._headers[key.title()]

    def __iter__(self) -> Iterator[str]:
        return iter(self._headers)

    def __len__(self) -> int:
        return len(self._headers)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        return key.title() in self._headers


class DjangoGuardResponse:
    def __init__(self, response: HttpResponse) -> None:
        self._response = response

    @property
    def status_code(self) -> int:
        result: int = self._response.status_code
        return result

    @property
    def headers(self) -> MutableMapping[str, str]:
        return cast(MutableMapping[str, str], self._response)

    @property
    def body(self) -> bytes | None:
        result: bytes | None = self._response.content
        return result


class DjangoResponseFactory:
    def create_response(self, content: str, status_code: int) -> DjangoGuardResponse:
        return DjangoGuardResponse(HttpResponse(content, status=status_code))

    def create_redirect_response(
        self, url: str, status_code: int
    ) -> DjangoGuardResponse:
        response = HttpResponse(status=status_code)
        response["Location"] = url
        return DjangoGuardResponse(response)


def unwrap_response(guard_response: Any) -> HttpResponse:
    if isinstance(guard_response, DjangoGuardResponse):
        return guard_response._response
    response = HttpResponse(
        guard_response.body,
        status=guard_response.status_code,
    )
    for key, value in guard_response.headers.items():
        response[key] = value
    return response
