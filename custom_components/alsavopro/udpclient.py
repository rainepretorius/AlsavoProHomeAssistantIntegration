"""Async UDP client for Alsavo Pro devices."""

import asyncio
import logging


_LOGGER = logging.getLogger(__name__)


class UDPClient:
    """Async UDP client for sending and receiving UDP packets."""
    def __init__(
        self,
        server_host,
        server_port,
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
        # Sending only
        def __init__(self, message):
            self.message = message
            self.transport = None

        def connection_made(self, transport):
            self.transport = transport
            self.transport.sendto(self.message)
            self.transport.close()

    class EchoClientProtocol(asyncio.DatagramProtocol):
        """Send a packet and collect every datagram returned within a short window."""

        def __init__(self, message, future, loop, idle_timeout=0.3):
            self.message = message
            self.future = future
            self.loop = loop
            self.transport = None
            self.idle_timeout = idle_timeout
            self._timeout_handle = None
            self._responses = []

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

    async def send_rcv(self, bytes_to_send):
        _LOGGER.debug(
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
                remote_addr=(self.server_host, self.server_port)
            )

            try:
                packets = await asyncio.wait_for(future, timeout=attempt_timeout)
                if len(packets) == 0:
                    raise TimeoutError("Alsavo Pro UDP request received no packets")
                _LOGGER.debug(
                    "Received %s packet(s) from %s:%s", len(packets), self.server_host, self.server_port
                )
                for packet in packets:
                    _LOGGER.debug(
                        "Received %s bytes from %s:%s: %s",
                        len(packet),
                        self.server_host,
                        self.server_port,
                        packet.hex(),
                    )
                return packets
            except asyncio.TimeoutError as err:
                last_error = err
                _LOGGER.warning(
                    "UDP attempt %s/%s timed out waiting %.1fs for response; %s",
                    attempt,
                    self.max_attempts,
                    attempt_timeout,
                    "retrying" if attempt < self.max_attempts else "giving up",
                )
            except TimeoutError as err:
                last_error = err
                _LOGGER.warning(
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

    async def send(self, bytes_to_send):
        transport, protocol = await self.loop.create_datagram_endpoint(
            lambda: self.SimpleClientProtocol(bytes_to_send),
            remote_addr=(self.server_host, self.server_port)
        )
        transport.close()
