#!/usr/bin/env python3
"""
Automated Pipeline End-to-End Test
"""
import sys
import time
import json
import threading
import paho.mqtt.client as mqtt
from ml_engine.inference_service import AnomalyInferenceEngine
from broker.embedded_broker import EmbeddedMQTTBroker
import asyncio

async def run_broker():
    broker = EmbeddedMQTTBroker(host="127.0.0.1", port=1883)
    await broker.start()

def start_broker_thread():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run_broker())

def test_pipeline():
    print("Testing end-to-end pipeline...")
    # Start broker in background thread
    t = threading.Thread(target=start_broker_thread, daemon=True)
    t.start()
    time.sleep(1.0)

    # Initialize inference engine
    engine = AnomalyInferenceEngine(models_dir="ml_engine/models", anomaly_threshold=0.55)

    # Subscribe to alerts and predictions
    results = []
    subscriber = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="TestSubscriber")
    
    def on_msg(client, userdata, msg):
        payload = json.loads(msg.payload.decode())
        results.append((msg.topic, payload))

    subscriber.on_message = on_msg
    subscriber.connect("127.0.0.1", 1883)
    subscriber.subscribe("edge/telemetry/prediction")
    subscriber.subscribe("edge/alerts/high_priority")
    subscriber.loop_start()

    time.sleep(0.5)

    # Simulate publisher
    publisher = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="TestPublisher")
    publisher.connect("127.0.0.1", 1883)

    # Send SYN Flood packet
    syn_flood = {
        "device_id": "test-esp32",
        "timestamp": int(time.time()*1000),
        "packet_rate": 3000.0,
        "byte_rate": 180000.0,
        "avg_packet_size": 60.0,
        "syn_ratio": 0.98,
        "ack_ratio": 0.01,
        "udp_ratio": 0.01,
        "icmp_ratio": 0.0,
        "unique_dst_ports": 2
    }

    # Run inference directly
    pred = engine.predict(syn_flood)
    assert pred["is_anomaly"] == True, f"Expected anomaly, got {pred}"
    assert pred["threat_type"] != "Normal", f"Expected attack threat type, got {pred['threat_type']}"
    print("Direct inference assertion passed: Anomaly detected, threat =", pred["threat_type"], ", latency =", pred["latency_ms"], "ms")

    # Publish prediction
    publisher.publish("edge/telemetry/prediction", json.dumps(pred))
    publisher.publish("edge/alerts/high_priority", json.dumps(pred))
    
    time.sleep(1.0)
    subscriber.loop_stop()
    publisher.disconnect()
    subscriber.disconnect()

    assert len(results) >= 2, f"Expected at least 2 MQTT messages received, got {len(results)}"
    print(f"MQTT End-to-end verified! Received {len(results)} messages on subscribed topics.")
    print("[ALL TESTS PASSED SUCCESSFULLY!]")

if __name__ == "__main__":
    test_pipeline()
