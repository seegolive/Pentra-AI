# Explicit imports ensure knowledge tasks are registered when the Celery worker
# starts. Other task modules have pre-existing VulnClass.XSS bugs and are
# excluded until that enum is fixed.
from app.tasks import knowledge_scrape, knowledge_update  # noqa: F401
