import os

from celery import Celery
from django.conf import settings

"""
setting up a Celery worker for a Django application, configuring it with settings from Django, and enabling it to find tasks defined in installed Django apps.
"""

# this enables the use of Django settings in the Celery configuration
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.local")

app = Celery("gchin_apartments")

# the namespace means to look for settings prefixed with CELERY_
app.config_from_object("django.conf:settings", namespace="CELERY")

app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)
