"""Default ASGI entry point: `uvicorn gateway.main:app`."""

from .app import create_app


app = create_app()
