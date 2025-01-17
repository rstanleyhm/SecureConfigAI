import os
import pytest
from app.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    client = app.test_client()
    yield client

def test_upload_valid_file(client, tmp_path):
    filepath = tmp_path / "sample.env"
    filepath.write_text("DEBUG=True\nPASSWORD=12345\nALLOWED_HOSTS=*")
    data = {'file': (open(filepath, 'rb'), 'sample.env')}
    response = client.post('/api/upload', data=data)
    assert response.status_code == 200
    assert "File uploaded successfully" in response.json["message"]

def test_upload_invalid_file(client, tmp_path):
    filepath = tmp_path / "sample.txt"
    filepath.write_text("This is a plain text file and should not be accepted.")
    data = {'file': (open(filepath, 'rb'), 'sample.txt')}
    response = client.post('/api/upload', data=data)
    assert response.status_code == 400
    assert "Unsupported file type" in response.json["error"]
