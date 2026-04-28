#!/bin/bash
export PATH="/home/runner/workspace/.pythonlibs/bin:$PATH"
export PYTHONPATH="/home/runner/workspace/.pythonlibs/lib/python3.11/site-packages:$PYTHONPATH"
exec python3 -m gunicorn --bind=0.0.0.0:5000 --reuse-port main:app
