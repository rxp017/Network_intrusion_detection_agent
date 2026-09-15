import pandas as pd
import pytest
from fastapi.testclient import TestClient

from main import app
from model import ROOT, STRIPPED_COLUMNS, ModelBundle


@pytest.fixture(scope="session")
def bundle():
    return ModelBundle()


@pytest.fixture(scope="session")
def flow():
    row = pd.read_csv(ROOT / "data" / "replay.csv").iloc[0].to_dict()
    return {k: v for k, v in row.items() if k not in STRIPPED_COLUMNS}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client
