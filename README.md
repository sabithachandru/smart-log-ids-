# Smart Log Monitoring and Intrusion Detection System

AI powered web application that classifies uploaded system log files as **Normal File** or **Intrusion Detected**.

**Tech stack:** HTML, Tailwind CSS, JavaScript, Python (Flask), scikit-learn (TF-IDF + Logistic Regression), MySQL

## Modules
Home Page, Sign Up, Login, Dashboard, About Project, Upload Log File, Results, Intrusion Files, Normal Files.

## How it works
Sign Up / Login -> Dashboard -> Upload Log File -> TF-IDF vectorizer + Logistic Regression classify each log line -> if any line is classified as an intrusion the file is **Intrusion Detected**, otherwise **Normal File** -> result saved in MySQL.

The model is trained when the application starts (about 2 seconds) from a labelled sample of log lines, so no model file is needed. Replace the sample data in `model.py` with your own dataset to retrain on it.

## Database (MySQL)
- `users` (id, username, password, created_at)
- `logs` (id, filename, prediction, uploaded_time, username)

Tables are created automatically on first start.

## Run locally (Windows, XAMPP/WAMP)
1. Start MySQL, create database `smart_log_ids`
2. In the project folder:
   ```
   pip install -r requirements.txt
   set DB_HOST=localhost
   set DB_USER=root
   set DB_PASSWORD=
   set DB_NAME=smart_log_ids
   python app.py
   ```
3. Open http://127.0.0.1:5000

Without `DB_HOST` a local SQLite file is used instead.

## Demo login
username: `demo`  password: `demo123`

Test files are in `sample_logs/`.

## Deploy on Render with free cloud MySQL (TiDB Cloud)
1. Create a free TiDB Cloud Starter (MySQL compatible) cluster, note host, port (4000), user, password
2. Create database: `CREATE DATABASE smart_log_ids;`
3. Push this folder to GitHub, then Render -> New -> Web Service -> select the repo
4. Build command: `pip install -r requirements.txt`   Start command: `gunicorn app:app`
5. Environment variables: `SECRET_KEY`, `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME=smart_log_ids`, `DB_SSL=true`
6. Health check path: `/health`
