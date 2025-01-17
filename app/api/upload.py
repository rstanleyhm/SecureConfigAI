# app/api/upload.py

import os
from flask import Blueprint, request, jsonify

upload_api = Blueprint('upload_api', __name__)
UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'env', 'yaml', 'json', 'conf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@upload_api.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        return jsonify({"message": "File uploaded successfully", "filepath": filepath}), 200

    return jsonify({"error": "Unsupported file type"}), 400
