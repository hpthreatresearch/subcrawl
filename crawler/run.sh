service clamav-daemon start
service supervisor start
gunicorn app.main:app -b 0.0.0.0:8000 --reload --workers 4