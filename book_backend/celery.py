import os
from celery import Celery
from django.conf import settings

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "book_backend.settings")

celery = Celery("book_backend")
celery.config_from_object("django.conf:settings", namespace="CELERY")
celery.autodiscover_tasks()