#!/bin/bash

python manage.py makemigrations
python manage.py migrate --noinput

python manage.py createsuperuser --no-input

celery -A parent_control worker -l INFO &
celery -A parent_control beat -l INFO &
tail -f /dev/null

# https://stackoverflow.com/questions/49693148/running-celery-worker-beat-in-the-same-container#comment101086902_49693247

(gunicorn parent_control.wsgi --user pc_user --bind 0.0.0.0:8010 --workers 3) &
sudo nginx
