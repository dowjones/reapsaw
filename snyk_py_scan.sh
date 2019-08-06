#!/usr/bin/env bash
cd /tmp
virtualenv venv
source ./venv/bin/activate
cd /code
pip install -r requirements.txt
snyk test --json > $1
deactivate