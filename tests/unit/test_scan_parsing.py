import pytest
from app.api.scan import parse_file


@pytest.fixture
def sample_env_file(tmp_path):
    filepath = tmp_path / "sample.env"
    filepath.write_text("DEBUG=True\nPASSWORD=12345\nALLOWED_HOSTS=*")
    return str(filepath)


def test_parse_env_file(sample_env_file):
    content, error = parse_file(sample_env_file)
    assert error is None
    assert content == {"DEBUG": "True", "PASSWORD": "12345", "ALLOWED_HOSTS": "*"}
