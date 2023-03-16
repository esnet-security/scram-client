#!/usr/bin/env python3

import json
import logging
import os
import socket
import sys
import time
import traceback
import walrus
import datetime
import requests
import configparser

# Define logging
################

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

root = logging.getLogger()
root.setLevel(os.environ.get("SCRAM_LOGLEVEL", "INFO"))
root.addHandler(handler)

logging.getLogger("requests").setLevel(os.environ.get("SCRAM_LOGLEVEL", "WARNING"))

SCRAM_SOURCE = os.environ.get("SCRAM_SOURCE", socket.gethostname())
PROM_PORT = os.environ.get("SCRAM_PROMETHEUS_PORT", "9001")

SCRAM_HOST = os.environ.get("SCRAM_HOST","")
SCRAM_UUID = os.environ.get("SCRAM_UUID","")

if(SCRAM_HOST == "" or SCRAM_UUID == ""):
    config = configparser.ConfigParser()
    config.read('/etc/sysconfig/scram-client.conf')
    if(SCRAM_HOST == ""):
        try:
            SCRAM_HOST = config.get('SCRAM','SCRAM_HOST')
        except:
            logging.critical(f"No SCRAM_HOST set in env or conf file")
            sys.exit(1)
    if(SCRAM_UUID == ""):
        try:
            SCRAM_UUID = config.get('SCRAM','SCRAM_UUID')
        except:
            logging.critical(f"No SCRAM_UUID set in env or conf file")
            sys.exit(1)

subcommands = ["block", "queue", "run_queue"]

usage = (
    f"Usage: {sys.argv[0]} <" + "|".join(subcommands) + ">\n"
    "\n"
    "    block: Block a single IP, bypassing the queue.\n"
    "    queue: Add an IP to the queue.\n"
    "    run_queue: Attempt to block IPs in the queue, removing them if successful.\n"
    "\n"
    "    block and queue expect information passed on stdin, one variable per line, as follows:\n"
    "\n"
    "        ip: IP that is being blocked\n"
    "        note: The name of the notice\n"
    "        msg: The descriptive message\n"
    "        sub: Optional. Unused.\n"
    "        expiration time: YYYY-MM-DD HH:MM\n"
    "\n"
    "    run_queue takes no parameters.\n"
)

# Prometheus Exporter
####################

from prometheus_client import start_http_server, Counter, Gauge, Summary
BLOCK_TIME = Summary('scram_block_processing_seconds', 'Time spent blocking IPs')
QUEUE_SIZE = Gauge('scram_queue_size', 'Elements in the queue')
DEQUEUES_ATTEMPTED = Counter('scram_dequeues_attempted', 'Number of times we tried to remove something from the queue')
DEQUEUES_SUCCESSFUL = Counter('scram_dequeues_successful', 'Number of times we successfully removed something from the queue')
LAST_SUCCESSFUL_INSERTION = Gauge('scram_last_successful_push', 'Timestamp of our last successful queue insertion')
LAST_SUCCESSFUL_REMOVAL = Gauge('scram_last_successful_pop', 'Timestamp of our last successful queue removal')


@BLOCK_TIME.time()
def block(cidr, why, duration):
    """Block a single IP address"""
    
    source = SCRAM_SOURCE
#    autoscale = 1

    logging.debug("Attempting to block %s for %s.", cidr, why)

    # Calculate expiration from provided duration (in seconds).
    duration = int(float(duration))
    expiration = datetime.datetime.now()
    expiration += datetime.timedelta(seconds=duration)
    expiration = expiration.strftime("%Y-%m-%d %H:%M")

    url = "https://" + SCRAM_HOST + "/api/v1/entries/"
    payload = {"route": cidr, "actiontype": "block", "who": source, "expiration": expiration,
    "comment": why, "uuid": SCRAM_UUID}

    r = requests.post(url,json=payload)

    if(r.status_code != 201):
        # if it's 403, 
        logging.warning(f"Block request returned status code {r.status_code}")
    else:
        logging.info("Successfully blocked %s for %s.", cidr, why)
    
    return True


def queue(cidr, why, duration):
    """Add a single IP address to the queue"""

    db = walrus.Database()

    # Add an empty message to create the stream
    db.xadd('pending_blocks', {'cidr': cidr, 'why': why, 'duration': duration})
    LAST_SUCCESSFUL_INSERTION.set_to_current_time()


def run_queue():
    """Run in a loop, checking the queue and blocking IPs as they appear."""

    logging.info("queue_loop started.")
    db = walrus.Database()

    # Add an empty message to create the stream
    db.xadd('pending_blocks', {'type': "null"})

    # Create the consumer group
    cg = db.consumer_group('blocked', 'pending_blocks')
    cg.create()
    
    while True:
        messages = cg.pending_blocks.read()
        if messages:
            for message in messages:
                msg_id, data = message
                data = { key.decode(): val.decode() for key, val in data.items() }
                try:
                    if 'cidr' in data and block(data['cidr'], data['why'], data['duration']):
                        cg.pending_blocks.ack(msg_id)
                    else:
                        print(data)
                except Exception:
                    logging.warning("Caught exception in block().")
                    logging.warning(traceback.format_exc())
        else:
            time.sleep(0.1)

    logging.warning("queue_loop ended.")
    

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in subcommands:
        print(usage)
        sys.exit(1)

    subcommand = sys.argv[1]
    if subcommand == 'run_queue':
        start_http_server(int(PROM_PORT))
        logging.info(f"Prometheus server started on port {PROM_PORT}.")
        run_queue()
    else:
        lines = sys.stdin.read().strip().split("\n")
        if len(lines) == 5:
            ip, note, msg, sub, duration = lines
        elif len(lines) == 4:
            ip, note, msg, duration = lines
            sub = ""
        else:
            logging.critical(f"{len(lines)} number of lines passed to subcommand {subcommand}. Was expecting 4 or 5.")
            print(usage)
            sys.exit(1)

        comment = f"{note}: {msg} {sub}"
        if subcommand == "block":
            block(ip, comment, duration)
        elif subcommand == "queue":
            queue(ip, comment, duration)    

if __name__ == "__main__":
    main()
