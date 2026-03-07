# worker.py — Celery worker entrypoint for running scan tasks

from celery import Celery
from config import settings

celery_app = Celery(
    "quantum-scanner",
    broker=settings.REDIS_URL, #redis receives the job
    backend=settings.REDIS_URL, #redis stores the result
    include=["tasks.scan_task"] #include the scan_task module
    # Celery discovers and registers tasks from tasks/scan_task.p
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    # Tracking
    task_track_started=True,         # marks task as STARTED not just PENDING
    worker_prefetch_multiplier=1,    # worker takes 1 job at a time, not greedy

    # Retries
    task_acks_late=True,             # job only removed from queue after success
    task_reject_on_worker_lost=True, # if worker crashes, job goes back to queue

    # Timeouts
    task_soft_time_limit=150,        # warns task at 150 seconds
    task_time_limit=180,             # kills task at 180 seconds

    # Results
    result_expires=3600,             # results kept in Redis for 1 hour
)