from django.http import HttpRequest, HttpResponse, JsonResponse
from django.urls import path


def index(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"message": "Hello, World!"})


def protected(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"message": "Protected endpoint"})


def health(request: HttpRequest) -> HttpResponse:
    return HttpResponse("OK", status=200)


urlpatterns = [
    path("", index, name="index"),
    path("api/protected/", protected, name="protected"),
    path("health/", health, name="health"),
]
