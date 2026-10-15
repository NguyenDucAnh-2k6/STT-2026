"""Preserve dissector content separately from normalized model features."""
from typing import Any


def extract_raw_content(raw: dict[str, str], types: dict[str, str],
                        capture_truncated: bool) -> dict[str, Any]:
    layers = raw.get("frame.protocols", "").split(":")
    encrypted = any(layer in ("tls", "ssl", "quic") for layer in layers)
    payload = raw.get("tcp.payload", "")
    text = None
    byte_count = None
    decode_status = "not_observed"
    if payload:
        try:
            data = bytes.fromhex(payload.replace(":", ""))
            byte_count = len(data)
            if encrypted:
                decode_status = "encrypted_transport"
            else:
                try:
                    text = data.decode("utf-8", errors="strict")
                    decode_status = "utf8_valid"
                except UnicodeDecodeError:
                    decode_status = "non_utf8"
        except ValueError:
            decode_status = "invalid_hex"
    body = raw.get("http.file_data", "")
    # Empty denotes absent; the literal text "0" and surrounding whitespace
    # are real content here, not the categorical feature sentinel.
    return {"content_schema_version": 1,
            "content_scope": "packet-fields-first-occurrence",
            "content_capture_truncated": capture_truncated,
            "content_encrypted_transport": encrypted,
            "raw_tcp_payload_hex": payload or None,
            "raw_tcp_payload_text": text,
            "raw_tcp_payload_byte_count": byte_count,
            "raw_tcp_payload_decode_status": decode_status,
            "raw_http_query": raw.get("http.request.uri.query") or None,
            "raw_http_uri": raw.get("http.request.full_uri") or None,
            "raw_http_method": raw.get("http.request.method") or None,
            "raw_http_body": body or None,
            "raw_http_body_field_type": types.get("http.file_data", "unknown"),
            "raw_http_body_completeness": "dissector_field_only" if body else "not_observed",
            "raw_mqtt_message": raw.get("mqtt.msg") or None,
            "raw_mqtt_message_field_type": types.get("mqtt.msg", "unknown"),
            "raw_mqtt_topic": raw.get("mqtt.topic") or None,
            "raw_packet_info": raw.get("_ws.col.Info") or None}
