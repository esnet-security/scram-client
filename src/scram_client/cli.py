#!/usr/bin/env python3
"""
SCRAM Client CLI
"""

import configparser
import datetime
import logging
import os
import socket
import sys
import time
import traceback
import uuid

import click
import requests
import walrus
from prometheus_client import Summary, Gauge, start_http_server

# Constants
REDIS_STREAM_KEY = "pending_blocks"
CONSUMER_GROUP = "blocked"
CONFIG_PATH = "/etc/sysconfig/scram-client.conf"

# Globals
retry_counts = {}  # msg_id -> retry_count for failed messages


# Create module level database
class Config:
    def __init__(self):
        self.db = walrus.Database()

config = Config()


# Logging
class OneLineExceptionFormatter(logging.Formatter):
    def formatException(self, exc_info):
        result = super().formatException(exc_info)
        return repr(result)

    def format(self, record):
        result = super().format(record)
        if record.exc_text:
            result = result.replace("\n", "")
        return result


handler = logging.StreamHandler()
formatter = OneLineExceptionFormatter(logging.BASIC_FORMAT)
handler.setFormatter(formatter)

logger = logging.getLogger()
logger.setLevel(os.environ.get("SCRAM_LOGLEVEL", "INFO"))
logger.addHandler(handler)

# Prometheus
SCRAM_SOURCE = os.environ.get("SCRAM_SOURCE", socket.gethostname())
PROM_PORT = int(os.environ.get("SCRAM_PROMETHEUS_PORT", "9001"))
SCRAM_HOST = os.environ.get("SCRAM_HOST", "")
SCRAM_UUID = os.environ.get("SCRAM_UUID", "")

if not SCRAM_HOST or not SCRAM_UUID:
    conf = configparser.ConfigParser()
    conf.read(CONFIG_PATH)
    if not SCRAM_HOST:
        try:
            SCRAM_HOST = conf.get("SCRAM", "SCRAM_HOST")
        except Exception:
            error_message = "No SCRAM_HOST set in env or conf file"
            logger.critical(error_message)
            raise click.ClickException(error_message)
    if not SCRAM_UUID:
        try:
            SCRAM_UUID = conf.get("SCRAM", "SCRAM_UUID")
        except Exception:
            error_message = "No SCRAM_UUID set in env or conf file"
            logger.critical(error_message)
            raise click.ClickException(error_message)

BLOCK_TIME = Summary("scram_block_processing_seconds", "Time spent blocking IPs")
LAST_SUCCESSFUL_INSERTION = Gauge(
    "scram_last_successful_push", "Timestamp of our last successful queue insertion"
)


# Core Logic
@BLOCK_TIME.time()
def block_impl(cidr: str, why: str, duration: str) -> bool:
    """Block a single IP address."""

    source = SCRAM_SOURCE

    logger.debug(f"Attempting to block {cidr} for {why}.")

    # Calculate expiration from provided duration (in seconds).
    duration_int = int(float(duration))
    expiration = datetime.datetime.now()
    expiration += datetime.timedelta(seconds=duration_int)
    expiration_str = expiration.strftime("%Y-%m-%d %H:%M")

    url = f"https://{SCRAM_HOST}/api/v1/entries/"
    payload = {
        "route": cidr,
        "actiontype": "block",
        "who": source,
        "expiration": expiration_str,
        "comment": why,
        "uuid": SCRAM_UUID,
    }

    try:
        r = requests.post(url, json=payload)
        logger.info(f"Successfully blocked {cidr} for {why} with status code {r.status_code}.")

        return True
    except requests.exceptions.HTTPError as e:
        logger.warning(f"Block request failed: {e}")
        logger.debug(f"Failed block request response content: {e}")

        return False


def attempt_block(data: dict[str, str]) -> bool:
    """Attempt to block an IP. Returns True if successful."""
    return "cidr" in data and block_impl(data["cidr"], data["why"], data["duration"])


def move_to_failed(cg: walrus.ConsumerGroup, msg_id: str, data: dict[str, str]) -> None:
    """Move message to the failed stream."""
    failed_data = data.copy()
    config.db.xadd(FAILED_STREAM_KEY, failed_data)
    cg.pending_blocks.delete(msg_id)


def process_message(cg: walrus.ConsumerGroup, msg_id: str, data: dict[str, str]) -> None:
    """Process a message from the stream."""
    try:
        if "cidr" in data and block_impl(data["cidr"], data["why"], data["duration"]):
            cg.pending_blocks.delete(msg_id)
            root.info(
                f"Deleted message ({data.get('cidr')}) from queue after blocking."
            )
        else:
            root.warning(
                f"Failed to block message, not deleting, just acking. Data: {data}"
            )
            cg.pending_blocks.ack(msg_id)
    except Exception:
        root.warning("Caught exception in block().")
        root.warning(traceback.format_exc())
        cg.pending_blocks.ack(msg_id)


acked_retries = {}

def retry_acked_messages(cg: walrus.ConsumerGroup) -> None:
    """Retry failed messages."""
    acked_messages = cg.pending_blocks.acked()
    for msg_id, data in acked_messages:
        if msg_id not in acked_retries:
            acked_retries[msg_id] = 0
        if acked_retries[msg_id] < 4:
            data = {key.decode(): val.decode() for key, val in data.items()}
            process_message(cg, msg_id, data)
            acked_retries[msg_id] += 1
        else:
            cg.pending_blocks.delete(msg_id)
            del acked_retries[msg_id]
            root.info(f"Dropped message {msg_id} after 3 retries.")


def queue_impl(cidr: str, why: str, duration: str) -> None:
    """Add a single IP address to the queue."""
    db = walrus.Database()
    db.xadd(REDIS_STREAM_KEY, {"cidr": cidr, "why": why, "duration": duration})
    LAST_SUCCESSFUL_INSERTION.set_to_current_time()


def run_queue_impl() -> None:
    """Run in a loop, checking the queue and blocking IPs as they appear."""

    logger.info("queue_loop started.")

    # Create the consumer group
    cg = db.consumer_group(CONSUMER_GROUP, REDIS_STREAM_KEY)
    cg.create()

    while True:
        messages = cg.pending_blocks.read()
        if messages:
            for msg_id, data in messages:
                data = {key.decode(): val.decode() for key, val in data.items()}
                process_message(cg, msg_id, data)
        else:
            time.sleep(0.1)



def register_impl(server: str) -> None:
    """Register this client with the SCRAM server."""
    url = f"https://{server}/api/v1/register_client/"
    new_scram_uuid = str(uuid.uuid4())
    payload = {"hostname": SCRAM_SOURCE, "uuid": new_scram_uuid}
    r = requests.post(url, json=payload)

    if r.status_code != 201:
        err_msg = (
            f"Error initializing new SCRAM client. \n \n Response: {r.content}"
        )
        logger.critical(err_msg)
        raise click.ClickException(err_msg)
    click.echo("Successfully registered new SCRAM client")
    click.echo(f"New UUID: {new_scram_uuid}")
    click.echo("Please ask your SCRAM admin to approve this client.")


def get_queue_size() -> int | None:
    """Return the number of entries in the pending_blocks stream."""
    try:
        return config.db.xlen(REDIS_STREAM_KEY)
    except Exception:
        root.warning("Failed to get pending_blocks queue size.")
        root.warning(traceback.format_exc())


def trim_queue_impl() -> int:
    """Trim all entries from the pending_blocks stream and return the number trimmed."""
    size = get_queue_size()
    try:
        config.db.xtrim(REDIS_STREAM_KEY, 0)
        return size
    except Exception:
        err_msg = "Failed to clear pending_blocks queue."
        logger.critical(err_msg)
        logger.critical(traceback.format_exc())
        raise click.ClickException(err_msg)


def list_queue_entries(limit: int = 100) -> list[dict[str, str]]:
    """
    List up to `limit` entries from the pending_blocks queue.
    Returns a list of dicts with 'cidr' and 'why' fields.
    """
    entries = []
    try:
        results = config.db.xrange(REDIS_STREAM_KEY, count=limit)
        for entry_id, data in results:
            decoded = {k.decode(): v.decode() for k, v in data.items()}
            entries.append(
                {
                    "cidr": decoded.get("cidr", ""),
                    "why": decoded.get("why", ""),
                    "duration": decoded.get("duration", ""),
                    "id": entry_id.decode(),
                }
            )
    except Exception:
        err_msg = "Failed to list entries from pending_blocks queue."
        logger.warning(err_msg)
        logger.warning(traceback.format_exc())
        raise click.ClickException(err_msg)
    return entries


def list_acked_entries(limit: int = 100) -> list[dict[str, str]]:
    """
    List up to `limit` acknowledged entries from the pending_blocks stream.
    Returns a list of dicts with 'cidr', 'why', 'duration', and 'id' fields.

    TODO: Delete this and don't let this go to prod, this is for testing purposes only and is a hack (like me)
    """
    entries = []
    try:
        cg = config.db.consumer_group(CONSUMER_GROUP, REDIS_STREAM_KEY)
        pending_info = cg.pending_blocks.pending()
        pending_ids = set(item["message_id"] for item in pending_info)
        all_entries = config.db.xrange(REDIS_STREAM_KEY, count=limit * 2)
        count = 0
        for entry_id, data in all_entries:
            if entry_id not in pending_ids:
                decoded = {k.decode(): v.decode() for k, v in data.items()}
                entries.append(
                    {
                        "cidr": decoded.get("cidr", ""),
                        "why": decoded.get("why", ""),
                        "duration": decoded.get("duration", ""),
                        "id": entry_id.decode(),
                    }
                )
                count += 1
                if count >= limit:
                    break
    except Exception:
        err_msg = (
            "Failed to list acknowledged entries from pending_blocks stream."
        )
        logger.warning(err_msg)
        logger.warning(traceback.format_exc())
        raise click.ClickException(err_msg)
    return entries


# CLI Stuff
@click.group()
def cli() -> None:
    """SCRAM client command line interface."""
    pass


@cli.command(name="run_queue")
def run_queue() -> None:
    """Attempt to block IPs in the queue, removing them if successful."""
    start_http_server(PROM_PORT)
    logger.info(f"Prometheus server started on port {PROM_PORT}.")
    run_queue_impl()


@cli.command(name="register")
@click.argument("server", type=str)
def register(server: str) -> None:
    """Generate a random UUID and send it to the SCRAM server."""
    register_impl(server)


@cli.command(name="block")
def block() -> None:
    """Block a single IP, bypassing the queue. Reads input from stdin."""
    lines = sys.stdin.read().strip().split("\n")
    if len(lines) == 5:
        ip, note, msg, sub, duration = lines
    elif len(lines) == 4:
        ip, note, msg, duration = lines
        sub = ""
    else:
        err_msg = f"{len(lines)} number of lines passed to subcommand block. Was expecting 4 or 5."
        logger.critical(err_msg)
        raise click.ClickException(err_msg)
    comment = f"{note}: {msg} {sub}"
    block_impl(ip, comment, duration)


@cli.command(name="queue")
def queue() -> None:
    """Add an IP to the queue. Reads input from stdin."""
    lines = sys.stdin.read().strip().split("\n")
    if len(lines) == 5:
        ip, note, msg, sub, duration = lines
    elif len(lines) == 4:
        ip, note, msg, duration = lines
        sub = ""
    else:
        err_msg = f"{len(lines)} number of lines passed to subcommand queue. Was expecting 4 or 5."
        logger.critical(err_msg)
        raise click.ClickException(err_msg)
    comment = f"{note}: {msg} {sub}"
    queue_impl(ip, comment, duration)


@cli.command(name="trim_queue")
def trim_queue() -> None:
    """Remove all entries from the pending_blocks queue and report how many were trimmed."""
    trimmed = trim_queue_impl()
    logger.info(f"Cleared {trimmed} entries from pending_blocks queue.")
    click.echo(f"Cleared {trimmed} entries from pending_blocks queue.")


# TODO: add a command for getting the failed_queue_size
@cli.command(name="queue_size")
def queue_size() -> None:
    """Show the number of entries in the pending_blocks queue."""
    size = get_queue_size()
    logger.info(f"pending_blocks queue size: {size}")
    click.echo(f"pending_blocks queue size: {size}")


@cli.command(name="list_queue")
@click.option(
    "--limit", default=100, show_default=True, help="Maximum number of entries to show."
)
def list_queue(limit: int) -> None:
    """List CIDR values (with messages) in the block queue, limited to N entries."""
    entries = list_queue_entries(limit)
    if not entries:
        click.echo("No entries in the block queue.")
        return
    for entry in entries:
        click.echo(
            f"{entry['id']}: {entry['cidr']} - {entry['why']} (duration: {entry['duration']})"
        )


@cli.command(name="list_acked")
@click.option(
    "--limit", default=100, show_default=True, help="Maximum number of entries to show."
)
def list_acked(limit: int) -> None:
    """List CIDR values (with messages) in the block queue that have been acked, limited to N entries."""
    entries = list_acked_entries(limit)
    if not entries:
        click.echo("No acknowledged entries in the block queue.")
        return
    for entry in entries:
        click.echo(
            f"{entry['id']}: {entry['cidr']} - {entry['why']} (duration: {entry['duration']})"
        )


if __name__ == "__main__":
    cli()
