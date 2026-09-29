import shutil
from pathlib import Path

import pytest

from app import create_app
from app.config import Settings
from app.models.db import SessionLocal, init_engine

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "exports" / "sample-tenant"


@pytest.fixture
def export_dir(tmp_path) -> Path:
    """A writable copy of the sample export so tests can mutate it."""
    d = tmp_path / "export"
    shutil.copytree(SAMPLE, d)
    return d


@pytest.fixture
def settings(tmp_path, export_dir) -> Settings:
    return Settings(DATABASE_URL=f"sqlite:///{tmp_path / 'test.db'}", OKTA_SOURCE="file",
                    OKTA_EXPORT_DIR=str(export_dir), FLASK_SECRET_KEY="test", _env_file=None)


@pytest.fixture
def db(settings):
    init_engine(settings.database_url)
    s = SessionLocal()
    yield s
    SessionLocal.remove()


@pytest.fixture
def app(settings):
    flask_app = create_app(settings)
    flask_app.config["TESTING"] = True
    yield flask_app
    SessionLocal.remove()


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client) -> str:
    client.get("/")
    with client.session_transaction() as sess:
        return sess["_csrf"]
