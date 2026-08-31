from django.http import HttpRequest, JsonResponse
from django.urls import path
from django.views.decorators.http import require_GET

from advanced_app.models import message_response
from advanced_app.security import guard


@require_GET
@guard.require_ip(whitelist=["127.0.0.1", "10.0.0.0/8"])
def ip_whitelist_only(request: HttpRequest) -> JsonResponse:
    return JsonResponse(message_response("Access granted from whitelisted IP"))


@require_GET
@guard.require_ip(blacklist=["192.168.1.0/24", "172.16.0.0/12"])
def ip_blacklist_demo(request: HttpRequest) -> JsonResponse:
    return JsonResponse(message_response("Access granted - not blacklisted"))


@require_GET
@guard.block_countries(["CN", "RU", "KP"])
def block_specific_countries(request: HttpRequest) -> JsonResponse:
    return JsonResponse(message_response("Access granted - country not blocked"))


@require_GET
@guard.allow_countries(["US", "CA", "GB", "AU"])
def allow_specific_countries(request: HttpRequest) -> JsonResponse:
    return JsonResponse(message_response("Access granted from allowed country"))


@require_GET
@guard.block_clouds()
def block_all_clouds(request: HttpRequest) -> JsonResponse:
    return JsonResponse(message_response("Access granted - not from cloud"))


@require_GET
@guard.block_clouds(["AWS"])
def block_aws_only(request: HttpRequest) -> JsonResponse:
    return JsonResponse(message_response("Access granted - not from AWS"))


@require_GET
@guard.bypass(["rate_limit", "ip"])
def bypass_specific_checks(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        message_response(
            "This endpoint bypasses rate limiting and IP/country/cloud checks",
            details={
                "bypassed_checks": ["rate_limit", "ip"],
            },
        )
    )


urlpatterns = [
    path("ip-whitelist", ip_whitelist_only),
    path("ip-blacklist", ip_blacklist_demo),
    path("country-block", block_specific_countries),
    path("country-allow", allow_specific_countries),
    path("no-cloud", block_all_clouds),
    path("no-aws", block_aws_only),
    path("bypass-demo", bypass_specific_checks),
]
