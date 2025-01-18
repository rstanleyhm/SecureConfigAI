import sys
import os
from flask import Flask, render_template, request, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
import redis
import threading
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils.rules_loader import load_rules
from utils.scan_helpers import parse_file, scan_file

print("PYTHONPATH:", sys.path)

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'env', 'yaml', 'json'}

# Redis setup
redis_client = redis.Redis(host='redis', port=6379, db=0)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(url_for('home', error="No file selected"))

    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('home', error="No file selected"))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Publish the file path to a Redis channel
        redis_client.publish('file_channel', filepath)

        return jsonify({"message": "File received and queued for scanning"}), 200

    return redirect(url_for('home', error="Unsupported file type"))

def process_file_subscriber():
    pubsub = redis_client.pubsub()
    pubsub.subscribe('file_channel')

    for message in pubsub.listen():
        if message['type'] == 'message':
            filepath = message['data'].decode('utf-8')
            print(f"Processing file: {filepath}")

            # Parse and scan the file
            content, error = parse_file(filepath)
            if error:
                print(f"Error parsing file: {error}")
                continue

            rules = load_rules()
            findings = scan_file(content, rules)
            print(f"Findings for {filepath}: {findings}")

# Start Redis subscriber in a separate thread
thread = threading.Thread(target=process_file_subscriber, daemon=True)
thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
