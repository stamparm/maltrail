#!/bin/sh
set -e

# Start cron in background
service cron start

# Starte maltrail-Server im Vordergrund
exec python /opt/maltrail/server.py