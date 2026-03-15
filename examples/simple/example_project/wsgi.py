"""
WSGI config for the simple example project.

It exposes the WSGI callable as a module-level variable named ``application``.

Run with: gunicorn example_project.wsgi:application --bind 0.0.0.0:8000 --reload
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "example_project.settings")

application = get_wsgi_application()
