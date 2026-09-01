from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from cyberrisk_intel.db.models import Base


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            text("""
            CREATE VIRTUAL TABLE search_fts USING fts5(
                chunk_id UNINDEXED, entity_type UNINDEXED, title, body, tokenized,
                tokenize='unicode61'
            )
        """)
        )
    with Session(engine, autoflush=False) as database_session:
        yield database_session
        database_session.rollback()
