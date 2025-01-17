from flask import Flask
from app.api.upload import upload_api
from app.api.scan import scan_api

app = Flask(__name__)
app.register_blueprint(upload_api, url_prefix="/api")
app.register_blueprint(scan_api, url_prefix="/api")

if __name__ == "__main__":
    app.run(debug=True)
