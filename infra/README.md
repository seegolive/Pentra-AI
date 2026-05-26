"""Pentra AI — Docker Compose stack.

Services:
  db        PostgreSQL 16
  redis     Redis 7
  qdrant    Qdrant vector DB
  minio     MinIO object storage
  api       FastAPI backend
  worker    Celery worker
  web       Vite frontend (dev mode)

Usage:
  docker compose up -d            # start all
  docker compose up -d api web    # start specific services
  docker compose logs -f api      # follow logs
  docker compose down             # stop all
  docker compose down -v          # stop + delete volumes
"""
