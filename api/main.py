"""ASGI entry point:  uvicorn api.main:app --port 8000

Configuration comes from the environment (and a local .env file if present). Startup fails fast on
unsafe combinations (core.config.validate_startup): e.g. AUTH_PROVIDER=demo with LIVE execution or
with DEMO_MODE=false, or LIVE without HEALING_ENABLED, write credentials and DEMO_MODE=false.
"""

from dotenv import load_dotenv
from fastapi import FastAPI

from api.container import AppContainer
from api.routes import create_app
from core.config import Settings


def build_app() -> FastAPI:
    load_dotenv()
    return create_app(AppContainer(Settings.from_env()))


app = build_app()
