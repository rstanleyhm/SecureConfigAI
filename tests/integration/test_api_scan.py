import pytest
from app.app import app
from app.utils.rules_loader import load_rules


@pytest.fixture
def client():
    app.config["TESTING"] = True
    client = app.test_client()
    yield client


def test_scan_endpoint(client, tmp_path):
    filepath = tmp_path / "sample.env"
    filepath.write_text("DEBUG=True\nPASSWORD=12345\nALLOWED_HOSTS=*")

    response = client.post("/api/scan", json={"filepath": str(filepath)})
    assert response.status_code == 200
    assert len(response.json["issues"]) == 6  # Update expected count
