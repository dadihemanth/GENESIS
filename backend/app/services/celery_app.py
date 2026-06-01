from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.config import settings

celery_app = Celery(
    "genesis",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.services.tasks", "app.services.daemon_tasks"],
)

# Default queue remains ``research``. T23 adds optional capability queues —
# operators running multi-host can launch workers with ``-Q research,has-ghidra``
# and the dispatcher routes capability-sensitive tasks there. Tasks that
# don't declare a queue fall through to ``research`` which every worker
# serves.
celery_app.conf.task_routes = {
    "app.services.tasks.*": {"queue": "research"},
}
# T23 — capability queues a multi-host operator might spin up. None of these
# are auto-routed yet; callers that know their task needs a specific tool
# can use ``task.apply_async(queue="has-ghidra")`` to target a specialist
# worker. Registered here so the worker CLI accepts them.
celery_app.conf.task_queues = None  # let Celery auto-create as needed
celery_app.conf.task_default_queue = "research"
celery_app.conf.task_serializer = "json"
celery_app.conf.result_serializer = "json"
celery_app.conf.accept_content = ["json"]
celery_app.conf.timezone = "UTC"
celery_app.conf.enable_utc = True
celery_app.conf.task_track_started = True
celery_app.conf.task_acks_late = True
celery_app.conf.worker_prefetch_multiplier = 1

# v5 daemon beat schedule (T90, T91, T98, T101)
celery_app.conf.beat_schedule = {
    # T90 — cross-session pattern miner: every 6 hours
    "cross-session-miner": {
        "task": "app.services.daemon_tasks.run_cross_session_miner",
        "schedule": crontab(minute=0, hour="*/6"),
        "options": {"queue": "research"},
    },
    # T91 — CVE extrapolator: once per day at 03:00 UTC
    "cve-extrapolator": {
        "task": "app.services.daemon_tasks.run_cve_extrapolator",
        "schedule": crontab(minute=0, hour=3),
        "options": {"queue": "research"},
    },
    # T98 — surface watcher: every hour
    "surface-watcher": {
        "task": "app.services.daemon_tasks.run_surface_watcher",
        "schedule": crontab(minute=0),
        "options": {"queue": "research"},
    },
    # T101 — Neo4j graph compactor: every 12 hours
    "graph-compactor": {
        "task": "app.services.daemon_tasks.run_graph_compactor",
        "schedule": crontab(minute=0, hour="*/12"),
        "options": {"queue": "research"},
    },
    # T129 — threat intel ingestor: every 4 hours
    "threat-intel-ingestor": {
        "task": "app.services.daemon_tasks.run_threat_intel_ingestor",
        "schedule": crontab(minute=0, hour="*/4"),
        "options": {"queue": "research"},
    },
    # T130 — CVE variant matcher: every 6 hours (after ingestor has run)
    "cve-variant-matcher": {
        "task": "app.services.daemon_tasks.run_cve_variant_matcher",
        "schedule": crontab(minute=30, hour="*/6"),
        "options": {"queue": "research"},
    },
    # T151 — reward model trainer: daily at 02:00 UTC
    "reward-model-trainer": {
        "task": "app.services.daemon_tasks.run_reward_model_trainer",
        "schedule": crontab(minute=0, hour=2),
        "options": {"queue": "research"},
    },
    # T154 — drift detection: weekly on Sunday 04:00 UTC
    "drift-detection": {
        "task": "app.services.daemon_tasks.run_drift_detection",
        "schedule": crontab(minute=0, hour=4, day_of_week=0),
        "options": {"queue": "research"},
    },
    # validation milestone 7 — recall benchmark: weekly on Sunday 05:00 UTC (after drift check)
    "recall-benchmark": {
        "task": "app.services.daemon_tasks.run_recall_benchmark",
        "schedule": crontab(minute=0, hour=5, day_of_week=0),
        "options": {"queue": "research"},
    },
}
