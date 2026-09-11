#!/usr/bin/env python3
"""
Lightweight Embedded MQTT Broker (Pure Python, Zero External Dependencies)
==========================================================================
Cho phép chạy thử nghiệm toàn bộ hệ thống ngay trên máy tính mà không cần cài đặt
trước Mosquitto hay Docker. Hỗ trợ MQTT 3.1.1 cơ bản (CONNECT, PUBLISH, SUBSCRIBE, PING, QoS 0).
"""

import asyncio
import logging
import socket
import os
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("EmbeddedBroker")

def decode_remaining_length(reader_stream_or_bytes):
    multiplier = 1
    value = 0
    idx = 0
    while True:
        if isinstance(reader_stream_or_bytes, (bytes, bytearray)):
            if idx >= len(reader_stream_or_bytes):
                return None, idx
            encoded_byte = reader_stream_or_bytes[idx]
            idx += 1
        else:
            return None, 0
        value += (encoded_byte & 127) * multiplier
        multiplier *= 128
        if (encoded_byte & 128) == 0:
            break
    return value, idx

def encode_remaining_length(length: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = length % 128
        length = length // 128
        if length > 0:
            byte |= 0x80
        encoded.append(byte)
        if length <= 0:
            break
    return bytes(encoded)

def topic_matches(pattern: str, topic: str) -> bool:
    if pattern == "#":
        return True
    pattern_parts = pattern.split("/")
    topic_parts = topic.split("/")
    i = 0
    while i < len(pattern_parts):
        part = pattern_parts[i]
        if part == "#":
            return True
        if i >= len(topic_parts):
            return False
        if part != "+" and part != topic_parts[i]:
            return False
        i += 1
    return i == len(topic_parts)

class MQTTClientSession:
    def __init__(self, reader, writer, broker):
        self.reader = reader
        self.writer = writer
        self.broker = broker
        self.client_id = "unknown"
        self.subscriptions = set()

    async def handle(self):
        peer = self.writer.get_extra_info('peername')
        logger.info(f"Client ket noi tu: {peer}")
        try:
            while True:
                # Read fixed header first byte
                header_byte = await self.reader.read(1)
                if not header_byte:
                    break
                packet_type = header_byte[0] >> 4
                flags = header_byte[0] & 0x0F

                # Read remaining length
                rem_len = 0
                multiplier = 1
                while True:
                    lb = await self.reader.read(1)
                    if not lb:
                        return
                    byte_val = lb[0]
                    rem_len += (byte_val & 127) * multiplier
                    multiplier *= 128
                    if (byte_val & 128) == 0:
                        break

                # Read payload of length rem_len
                payload = b""
                if rem_len > 0:
                    payload = await self.reader.readexactly(rem_len)

                # Process packet
                if packet_type == 1:  # CONNECT
                    await self.handle_connect(payload)
                elif packet_type == 3:  # PUBLISH
                    await self.handle_publish(flags, payload)
                elif packet_type == 8:  # SUBSCRIBE
                    await self.handle_subscribe(payload)
                elif packet_type == 10:  # UNSUBSCRIBE
                    await self.handle_unsubscribe(payload)
                elif packet_type == 12:  # PINGREQ
                    # Send PINGRESP
                    self.writer.write(b"\xd0\x00")
                    await self.writer.drain()
                elif packet_type == 14:  # DISCONNECT
                    break
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            logger.debug(f"Loi xu ly client {self.client_id}: {e}")
        finally:
            self.broker.remove_client(self)
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
            logger.info(f"Client ngat ket noi: {self.client_id}")

    async def handle_connect(self, data):
        # Parse protocol name and client ID
        try:
            proto_len = (data[0] << 8) | data[1]
            proto_name = data[2:2 + proto_len].decode('utf-8', errors='ignore')
            offset = 2 + proto_len + 4  # skip proto level & flags & keepalive
            cid_len = (data[offset] << 8) | data[offset + 1]
            offset += 2
            self.client_id = data[offset:offset + cid_len].decode('utf-8', errors='ignore')
        except Exception:
            self.client_id = f"client_{id(self)}"
        
        logger.info(f"Client xac thuc: ID='{self.client_id}'")
        # Send CONNACK (Return code 0: Connection Accepted)
        self.writer.write(b"\x20\x02\x00\x00")
        await self.writer.drain()

    async def handle_publish(self, flags, data):
        qos = (flags >> 1) & 0x03
        topic_len = (data[0] << 8) | data[1]
        topic = data[2:2 + topic_len].decode('utf-8', errors='ignore')
        offset = 2 + topic_len

        packet_id = None
        if qos > 0:
            packet_id = (data[offset] << 8) | data[offset + 1]
            offset += 2

        msg_payload = data[offset:]
        
        # Broadcast to all matching subscribers
        self.broker.broadcast(topic, msg_payload, qos)

        # If QoS 1, reply with PUBACK
        if qos == 1 and packet_id is not None:
            puback = bytearray([0x40, 0x02, (packet_id >> 8) & 0xFF, packet_id & 0xFF])
            self.writer.write(puback)
            await self.writer.drain()

    async def handle_subscribe(self, data):
        packet_id = (data[0] << 8) | data[1]
        offset = 2
        return_codes = bytearray()

        while offset < len(data):
            tlen = (data[offset] << 8) | data[offset + 1]
            offset += 2
            sub_topic = data[offset:offset + tlen].decode('utf-8', errors='ignore')
            offset += tlen
            req_qos = data[offset]
            offset += 1

            self.subscriptions.add(sub_topic)
            return_codes.append(min(req_qos, 1))
            logger.info(f"Client '{self.client_id}' dang ky topic: '{sub_topic}'")

        # Send SUBACK
        rem_len = 2 + len(return_codes)
        suback = bytearray([0x90])
        suback.extend(encode_remaining_length(rem_len))
        suback.extend([(packet_id >> 8) & 0xFF, packet_id & 0xFF])
        suback.extend(return_codes)
        self.writer.write(suback)
        await self.writer.drain()

    async def handle_unsubscribe(self, data):
        packet_id = (data[0] << 8) | data[1]
        offset = 2
        while offset < len(data):
            tlen = (data[offset] << 8) | data[offset + 1]
            offset += 2
            sub_topic = data[offset:offset + tlen].decode('utf-8', errors='ignore')
            offset += tlen
            self.subscriptions.discard(sub_topic)

        # Send UNSUBACK
        self.writer.write(bytearray([0xB0, 0x02, (packet_id >> 8) & 0xFF, packet_id & 0xFF]))
        await self.writer.drain()

    def send_publish(self, topic: str, payload: bytes):
        topic_bytes = topic.encode('utf-8')
        tlen = len(topic_bytes)
        body = bytearray([(tlen >> 8) & 0xFF, tlen & 0xFF])
        body.extend(topic_bytes)
        body.extend(payload)

        packet = bytearray([0x30])  # PUBLISH QoS 0
        packet.extend(encode_remaining_length(len(body)))
        packet.extend(body)
        try:
            self.writer.write(packet)
        except Exception:
            pass

class EmbeddedMQTTBroker:
    def __init__(self, host="0.0.0.0", port=1883):
        self.host = host
        self.port = port
        self.clients = set()

    def add_client(self, client: MQTTClientSession):
        self.clients.add(client)

    def remove_client(self, client: MQTTClientSession):
        self.clients.discard(client)

    def broadcast(self, topic: str, payload: bytes, qos: int = 0):
        for client in list(self.clients):
            for sub in client.subscriptions:
                if topic_matches(sub, topic):
                    client.send_publish(topic, payload)
                    break

    async def start(self):
        server = await asyncio.start_server(self._handle_conn, self.host, self.port)
        logger.info(f"==================================================")
        logger.info(f" [Embedded Broker] MQTT dang lang nghe tai {self.host}:{self.port}")
        logger.info(f"==================================================")
        async with server:
            await server.serve_forever()

    async def _handle_conn(self, reader, writer):
        session = MQTTClientSession(reader, writer, self)
        self.add_client(session)
        await session.handle()

def check_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0

def start_embedded_broker(host: str = "0.0.0.0", port: int = 1883):
    """
    Khởi động Embedded MQTT Broker trên host & port chỉ định.
    Có thể gọi trực tiếp từ run_system.py hoặc chạy standalone.
    """
    if check_port_in_use(port):
        logger.warning(f"Port {port} da co tien trinh su dung (Mosquitto hoac Broker khac dang chay).")
        return

    broker = EmbeddedMQTTBroker(host=host, port=port)
    try:
        asyncio.run(broker.start())
    except KeyboardInterrupt:
        logger.info("Dung Embedded MQTT Broker.")


def main():
    host = os.getenv("MQTT_HOST", "0.0.0.0")
    port = int(os.getenv("MQTT_PORT", 1883))
    start_embedded_broker(host=host, port=port)


if __name__ == "__main__":
    main()
