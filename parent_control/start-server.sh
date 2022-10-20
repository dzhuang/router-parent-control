#!/bin/bash

python manage.py makemigrations
python manage.py migrate --noinput

python manage.py createsuperuser --no-input

(gunicorn parent_control.wsgi --user pc_user --bind 0.0.0.0:8010 --access-logfile /opt/parent_control/log/access_file_g.log --error-logfile /opt/parent_control/log/error_file_g.log --capture-output --enable-stdio-inheritance --workers 3) &
sudo nginx
