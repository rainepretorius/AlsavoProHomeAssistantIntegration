"""Standalone Alsavo Pro UDP probe with no external module dependencies.

Run directly on any machine with network access to the heat pump. The script
performs the UDP handshake and a single `query_all`, then prints a concise
summary of the returned payloads.
"""

import argparse
import asyncio
import hashlib
import logging
import os
import random
import struct
import sys
from datetime import datetime, timezone
from typing import Iterable, List, Optional


class UDPClient:
    """Async UDP client for sending and receiving UDP packets."""

    def __init__(
        self,
        server_host: str,
        server_port: int,
        *,
        idle_timeout: float = 0.3,
        request_timeout: float = 3.0,
        max_attempts: int = 3,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.loop = asyncio.get_running_loop()
        self.idle_timeout = idle_timeout
        self.request_timeout = request_timeout
        self.max_attempts = max_attempts

    class SimpleClientProtocol(asyncio.DatagramProtocol):
        def __init__(self, message: bytes):
            self.message = message
            self.transport = None

        def connection_made(self, transport):
            self.transport = transport
            self.transport.sendto(self.message)
            self.transport.close()

    class EchoClientProtocol(asyncio.DatagramProtocol):
        """Send a packet and collect every datagram returned within a short window."""

        def __init__(self, message: bytes, future: asyncio.Future, loop, idle_timeout=0.3):
            self.message = message
            self.future = future
            self.loop = loop
            self.transport = None
            self.idle_timeout = idle_timeout
            self._timeout_handle = None
            self._responses: List[bytes] = []

        def connection_made(self, transport):
            self.transport = transport
            self.transport.sendto(self.message)
            self._schedule_finish()

        def datagram_received(self, data, addr):
            self._responses.append(data)
            self._schedule_finish()

        def error_received(self, exc):
            if not self.future.done():
                self.future.set_exception(exc)
            if self.transport:
                self.transport.close()

        def connection_lost(self, exc):
            if not self.future.done():
                self.future.set_exception(ConnectionError("Connection lost"))

        def _schedule_finish(self):
            if self._timeout_handle:
                self._timeout_handle.cancel()
            self._timeout_handle = self.loop.call_later(self.idle_timeout, self._finish)

        def _finish(self):
            if not self.future.done():
                self.future.set_result(self._responses)
            if self.transport:
                self.transport.close()

    async def send_rcv(self, bytes_to_send: bytes) -> List[bytes]:
        logging.getLogger(__name__).debug(
            "Sending %s bytes to %s:%s: %s",
            len(bytes_to_send),
            self.server_host,
            self.server_port,
            bytes_to_send.hex(),
        )
        last_error: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            attempt_timeout = min(self.request_timeout * attempt, self.request_timeout * 2)
            future = self.loop.create_future()
            transport, protocol = await self.loop.create_datagram_endpoint(
                lambda: self.EchoClientProtocol(
                    bytes_to_send,
                    future,
                    self.loop,
                    idle_timeout=self.idle_timeout,
                ),
                remote_addr=(self.server_host, self.server_port),
            )

            try:
                packets = await asyncio.wait_for(future, timeout=attempt_timeout)
                if len(packets) == 0:
                    raise TimeoutError("Alsavo Pro UDP request received no packets")
                logging.getLogger(__name__).debug(
                    "Received %s packet(s) from %s:%s",
                    len(packets),
                    self.server_host,
                    self.server_port,
                )
                for packet in packets:
                    logging.getLogger(__name__).debug(
                        "Received %s bytes from %s:%s: %s",
                        len(packet),
                        self.server_host,
                        self.server_port,
                        packet.hex(),
                    )
                return packets
            except asyncio.TimeoutError as err:
                last_error = err
                logging.getLogger(__name__).warning(
                    "UDP attempt %s/%s timed out waiting %.1fs for response; %s",
                    attempt,
                    self.max_attempts,
                    attempt_timeout,
                    "retrying" if attempt < self.max_attempts else "giving up",
                )
            except TimeoutError as err:
                last_error = err
                logging.getLogger(__name__).warning(
                    "UDP attempt %s/%s returned no packets; %s",
                    attempt,
                    self.max_attempts,
                    "retrying" if attempt < self.max_attempts else "giving up",
                )
            finally:
                transport.close()

            await asyncio.sleep(0.05)

        raise TimeoutError(
            f"Alsavo Pro UDP request timed out after {self.max_attempts} attempts"
        ) from last_error

    async def send(self, bytes_to_send: bytes):
        transport, protocol = await self.loop.create_datagram_endpoint(
            lambda: self.SimpleClientProtocol(bytes_to_send),
            remote_addr=(self.server_host, self.server_port),
        )
        transport.close()


class PacketHeader:
    """Packet header used by Alsavo Pro UDP protocol."""

    def __init__(self, hdr: int, seq: int, csid: int, dsid: int, cmd: int, payload_length: int):
        self.hdr = hdr
        self.pad = 0
        self.seq = seq
        self.csid = csid
        self.dsid = dsid
        self.cmd = cmd
        self.payloadLength = payload_length

    def pack(self) -> bytes:
        return struct.pack("!BBHIIHH", self.hdr, self.pad, self.seq, self.csid, self.dsid, self.cmd, self.payloadLength)

    @staticmethod
    def unpack(data: bytes) -> "PacketHeader":
        unpacked_data = struct.unpack("!BBHIIHH", data)
        return PacketHeader(
            unpacked_data[0],
            unpacked_data[2],
            unpacked_data[3],
            unpacked_data[4],
            unpacked_data[5],
            unpacked_data[6],
        )


class Timestamp:
    def __init__(self):
        current_time = datetime.now(timezone.utc)
        self.year = current_time.year
        self.month = current_time.month
        self.day = current_time.day
        self.hour = current_time.hour
        self.min = current_time.minute
        self.sec = current_time.second
        self.tz = 2  # Placeholder

    def pack(self) -> bytes:
        return struct.pack("!HBBBBBB", self.year, self.month, self.day, self.hour, self.min, self.sec, self.tz)


class AuthIntro:
    def __init__(self, client_token: int, serial_inv: int):
        self.hdr = PacketHeader(0x32, 0, 0, 0, 0xF2, 0x28)
        self.act1, self.act2, self.act3, self.act4 = 1, 1, 2, 0
        self.clientToken = client_token
        self.pumpSerial = serial_inv
        self._uuid = [0x97E8CED0, 0xF83640BC, 0xB4DD57E3, 0x22ADC3A0]
        self.timestamp = Timestamp()

    def pack(self) -> bytes:
        packed_hdr = self.hdr.pack()
        packed_uuid = struct.pack("!IIII", *self._uuid)
        packed_data = struct.pack(
            "!BBBBIQ",
            self.act1,
            self.act2,
            self.act3,
            self.act4,
            self.clientToken,
            self.pumpSerial,
        ) + packed_uuid + self.timestamp.pack()
        return packed_hdr + packed_data


class AuthChallenge:
    def __init__(self, hdr: PacketHeader, act1: int, act2: int, act3: int, act4: int, server_token: int):
        self.hdr = hdr
        self.act1 = act1
        self.act2 = act2
        self.act3 = act3
        self.act4 = act4
        self.serverToken = server_token

    @staticmethod
    def unpack(data: bytes) -> "AuthChallenge":
        packet_hdr = PacketHeader.unpack(data[0:16])
        act1, act2, act3, act4, server_token = struct.unpack("!BBBBI", data[16:24])
        return AuthChallenge(packet_hdr, act1, act2, act3, act4, server_token)

    @property
    def is_authorized(self) -> bool:
        return self.act1 == 3 and self.act2 == 0 and self.act3 == 0 and self.act4 == 0


class AuthResponse:
    def __init__(self, csid: int, dsid: int, resp: bytes):
        self.hdr = PacketHeader(0x32, 0, csid, dsid, 0xF2, 0x1C)
        self.act1, self.act2, self.act3, self.act4 = 4, 0, 0, 3
        self.timestamp = Timestamp()
        self.response = bytes(resp)

    def pack(self) -> bytes:
        packed_data = struct.pack("!BBBB", self.act1, self.act2, self.act3, self.act4)
        return self.hdr.pack() + packed_data + self.response + self.timestamp.pack()


class Payload:
    """Config, Status or device info-payload packet."""

    def __init__(self, data_type: int, sub_type: int, size: int, start_idx: int, indices: int):
        self.type = data_type
        self.subType = sub_type
        self.size = size
        self.startIdx = start_idx
        self.indices = indices
        self.data: Iterable[int] = []

    def get_value(self, idx: int) -> int:
        if idx - self.startIdx < 0 or idx - self.startIdx > len(self.data):
            return 0
        return list(self.data)[idx - self.startIdx]

    @staticmethod
    def unpack(data: bytes) -> "Payload":
        unpacked_data = struct.unpack("!IHHHH", data[0:12])
        obj = Payload(unpacked_data[0], unpacked_data[1], unpacked_data[2], unpacked_data[3], unpacked_data[4])
        if obj.subType in (1, 2):
            obj.data = struct.unpack(">" + "H" * (obj.size // 2), data[12 : 12 + obj.size])
        else:
            obj.startIdx = 0
            obj.indices = 0
            obj.data = struct.unpack(">" + "H" * (obj.size // 2), data[8 : 8 + obj.size])
        return obj


class QueryResponse:
    """Query response containing data payload from heatpump."""

    def __init__(self, action: int, parts: int):
        self.action = action
        self.parts = parts
        self.__status: Optional[Payload] = None
        self.__config: Optional[Payload] = None
        self.__deviceInfo: Optional[Payload] = None

    def has_payload(self) -> bool:
        return any((self.__status, self.__config, self.__deviceInfo))

    def debug_summary(self) -> dict:
        def _payload_summary(payload: Optional[Payload]):
            if payload is None:
                return None
            values = list(payload.data)
            return {
                "start_idx": payload.startIdx,
                "count": len(values),
                "indices": payload.indices,
                "sample": values[:10],
            }

        return {
            "action": self.action,
            "parts": self.parts,
            "status": _payload_summary(self.__status),
            "config": _payload_summary(self.__config),
            "device_info": _payload_summary(self.__deviceInfo),
        }

    @staticmethod
    def unpack(data: bytes) -> "QueryResponse":
        unpacked_data = struct.unpack("!BBH", data[0:4])
        obj = QueryResponse(unpacked_data[0], unpacked_data[1])
        idx = 4

        while idx < len(data):
            payload = Payload.unpack(data[idx:])
            if payload.subType == 1:
                obj.__status = payload
            elif payload.subType == 2:
                obj.__config = payload
            elif payload.subType == 3:
                obj.__deviceInfo = payload
            idx += payload.size + 8

        return obj

    def get_status_value(self, idx: int) -> int:
        return self.__status.get_value(idx) if self.__status else 0

    def get_config_value(self, idx: int) -> int:
        return self.__config.get_value(idx) if self.__config else 0


def md5_hash(text: str) -> bytes:
    md5 = hashlib.md5()
    md5.update(text.encode())
    return md5.digest()


class AlsavoProbe:
    def __init__(self, host: str, port: int, serial: int, password: str):
        self.host = host
        self.port = port
        self.serial = serial
        self.password = password
        self.client_token: Optional[int] = None
        self.server_token: Optional[int] = None
        self.csid: Optional[int] = None
        self.dsid: Optional[int] = None
        self.client: Optional[UDPClient] = None

    async def send_and_receive(self, bytes_to_send: bytes) -> Optional[bytes]:
        responses = await self.client.send_rcv(bytes_to_send)
        if not responses:
            logging.debug("Received no response packets")
            return None

        merged = bytearray(responses[0])
        for extra in responses[1:]:
            merged.extend(extra[16:])

        primary_packet = bytes(merged)
        logging.debug(
            "Received %s response packet(s); merged payload into %s bytes for parsing",
            len(responses),
            len(primary_packet),
        )
        return primary_packet

    async def get_auth_challenge(self) -> AuthChallenge:
        auth_intro = AuthIntro(self.client_token, self.serial)
        response = await self.send_and_receive(bytes(auth_intro.pack()))
        return AuthChallenge.unpack(response)

    async def send_auth_response(self, ctx: hashlib._hashlib.HASH) -> bytes:
        resp = AuthResponse(self.csid, self.dsid, ctx.digest())
        return await self.send_and_receive(resp.pack())

    async def connect(self):
        logging.debug("Connecting to Alsavo Pro at %s:%s (serial=%s)", self.host, self.port, self.serial)

        self.client_token = random.randint(0, 65535)
        self.client = UDPClient(
            self.host,
            self.port,
            idle_timeout=2.5,
            request_timeout=12.0,
            max_attempts=3,
        )

        logging.debug("Asking for auth challenge with client token %s", self.client_token)
        auth_challenge = await self.get_auth_challenge()
        if not auth_challenge.is_authorized:
            raise ConnectionError("Invalid auth challenge packet (pump offline?)")

        self.csid = auth_challenge.hdr.csid
        self.dsid = auth_challenge.hdr.dsid
        self.server_token = auth_challenge.serverToken

        logging.debug(
            "Received handshake header=%s, CSID=%s, DSID=%s, server token=%s",
            {"hdr": hex(auth_challenge.hdr.hdr), "seq": auth_challenge.hdr.seq, "cmd": hex(auth_challenge.hdr.cmd)},
            hex(self.csid),
            hex(self.dsid),
            hex(self.server_token),
        )

        ctx = hashlib.md5()
        ctx.update(self.client_token.to_bytes(4, "big"))
        ctx.update(self.server_token.to_bytes(4, "big"))
        ctx.update(md5_hash(self.password))

        response = await self.send_auth_response(ctx)
        if response is None or len(response) == 0:
            raise ConnectionError("Server not responding to auth response")

        act = int.from_bytes(response[16:20], byteorder="little")
        logging.debug("Auth response action code: %s (raw=%s)", act, response.hex())
        if act != 0x00000005:
            raise ConnectionError("Server returned error in auth")
        logging.debug("Connected.")

    async def query_all(self) -> QueryResponse:
        logging.debug("socket.query_all")
        payload = b"\x08\x01\x00\x00\x00\x02\x00\x2e\xff\xff\x00\x00"
        header = PacketHeader(0x32, 0, self.csid, self.dsid, 0xF4, len(payload))
        packet = header.pack() + payload
        resp = await self.send_and_receive(packet)
        if resp is None:
            raise ConnectionError("query_all: no response")
        logging.debug("Query response header bytes: %s", resp[:16].hex())
        response = QueryResponse.unpack(resp[16:])
        if not response.has_payload():
            logging.debug(
                "Empty payload returned (action=%s, parts=%s); raw packet: %s",
                response.action,
                response.parts,
                resp.hex(),
            )
        return response


async def _probe(host: str, port: int, serial: int, password: str, debug: bool) -> int:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    client = AlsavoProbe(host, port, serial, password)
    try:
        await client.connect()
        response = await client.query_all()
    except Exception:  # pragma: no cover - requires networked device
        logging.exception("Probe failed")
        return 1

    summary = response.debug_summary()
    logging.info("Handshake and query succeeded")
    logging.info("Payload summary: %s", summary)

    status = summary.get("status") or {}
    config = summary.get("config") or {}
    print("\n=== Alsavo Pro probe results ===")
    print(f"Server: {host}:{port}  Serial: {serial}")
    if status:
        print(
            f"Status payload: count={status.get('count')} indices={status.get('indices')} sample={status.get('sample')}"
        )
    if config:
        print(
            f"Config payload: count={config.get('count')} indices={config.get('indices')} sample={config.get('sample')}"
        )
    if not status and not config:
        print("No payload data returned (status and config are empty)")

    return 0


def main(argv: list[str]) -> int:
    # Ensure UDP is usable on Windows: the Proactor loop lacks datagram support.
    if os.name == "nt":  # pragma: no cover - platform dependent
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:  # pragma: no cover - best-effort safeguard
            pass

    parser = argparse.ArgumentParser(description="Probe an Alsavo Pro heat pump over UDP")
    parser.add_argument("--host", required=True, help="Heat pump IP or cloud endpoint")
    parser.add_argument("--port", type=int, default=1194, help="UDP port (1194 local, 51192 cloud)")
    parser.add_argument("--serial", type=int, required=True, help="Heat pump serial number")
    parser.add_argument("--password", required=True, help="Alsavo Pro app password")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging")

    args = parser.parse_args(argv)

    return asyncio.run(_probe(args.host, args.port, args.serial, args.password, args.debug))


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    sys.exit(main(sys.argv[1:]))
