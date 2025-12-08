"""Common component lifecycle and ZeroMQ plumbing for collectors and alert engines."""

import threading
import zmq

from typing import Iterable, Optional



class BaseWorker:
    """Provides shared lifecycle and messaging helpers for system components."""

    def __init__(
        self,
        name: str,
        pub_topic: Optional[str] = None,
        sub_topics: Optional[Iterable[str]] = None,
        publisher: Optional[zmq.Socket] = None,
        subscriber: Optional[zmq.Socket] = None,
    ) -> None:
        self.name = name
        self.running = False
        self.pub_topic = pub_topic
        self.sub_topics = tuple(sub_topics or ())
        self.publisher = publisher
        self.subscriber = subscriber

    def start(self) -> None:
        print(f"[{self.name}] Starting...")
        self.running = True
        threading.Thread(target=self.run, daemon=True).start()

    def stop(self) -> None:
        print(f"[{self.name}] Stopping...")
        self.running = False

    def publish(self, topic: str, data: str) -> None:
        if not self.publisher:
            raise RuntimeError("Publisher socket not configured for component")

        message = f"{topic} {data}"
        # ZeroMQ PUB sockets send messages as strings, with the topic as a prefix.
        # The subscriber filters messages by topic prefix.
        # This sends the message to all subscribers of the topic.
        self.publisher.send_string(message)

        # Example:
        # If topic = "alerts" and data = "CPU usage high",
        # then message = "alerts CPU usage high"
        # All subscribers with zmq.SUBSCRIBE set to "alerts" will receive this message.
        # The delimiter between topic and data is a space.

    def subscribe(self, topic: str) -> None:
        if not self.subscriber:
            raise RuntimeError("Subscriber socket not configured for component")

        self.subscriber.setsockopt_string(zmq.SUBSCRIBE, topic)

    def run(self) -> None:
        raise NotImplementedError
