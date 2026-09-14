"""
Dashboard Backend Configuration
===============================
Cấu hình các tham số môi trường và đường dẫn cho Backend Dashboard.
"""

import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MQTT_BROKER_HOST = os.getenv("MQTT_HOST") or os.getenv("MQTT_BROKER_HOST", "127.0.0.1")
MQTT_BROKER_PORT = int(os.getenv("MQTT_PORT") or os.getenv("MQTT_BROKER_PORT", 1883))

# Web Dashboard Server port
WEB_PORT = int(os.getenv("PORT", 8000))

# Static frontend files directory
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
