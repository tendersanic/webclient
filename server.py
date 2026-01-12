import asyncio
import socket
import struct
import random
from aiohttp import web
from urllib.parse import urlparse

# --- Helper functions ---
def random_transaction_id():
    return random.randint(0, 0xFFFFFFFF)

def generate_peer_id():
    return b'-PY0001-' + bytes(f'{random.randint(0, 9999999999):010}', 'ascii')

def hex_to_bytes(hexstr):
    return bytes.fromhex(hexstr)

# --- Query UDP tracker ---
def query_tracker(tracker_host, tracker_port, info_hash_hex):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    # --- Connect Request ---
    protocol_id = 0x41727101980
    action = 0
    transaction_id = random_transaction_id()
    connect_req = struct.pack(">QII", protocol_id, action, transaction_id)
    sock.sendto(connect_req, (tracker_host, tracker_port))

    resp, _ = sock.recvfrom(16)
    if len(resp) < 16:
        return "Invalid response"
    connection_id = struct.unpack(">Q", resp[8:16])[0]

    # --- Announce Request ---
    action = 1
    transaction_id = random_transaction_id()
    info_hash = hex_to_bytes(info_hash_hex)
    peer_id = generate_peer_id()
    downloaded = 0
    left = 129241752
    uploaded = 0
    event = 1
    ip = 0
    key = random_transaction_id()
    num_want = 0xFFFFFFFF  # unsigned
    port = 6881

    announce_req = struct.pack(">QII20s20sQQQIIIIH",
        connection_id, action, transaction_id,
        info_hash, peer_id,
        downloaded, left, uploaded,
        event, ip, key, num_want, port
    )

    sock.sendto(announce_req, (tracker_host, tracker_port))
    resp, _ = sock.recvfrom(1024)
    sock.close()

    if len(resp) < 20:
        return "No peers found"

    peers = ""
    for i in range(20, len(resp), 6):
        if(peers!=""):peers+=",";
        ip_bytes = resp[i:i+4]
        port_bytes = resp[i+4:i+6]
        if len(ip_bytes) < 4 or len(port_bytes) < 2:
            break
        ip_str = ".".join(str(b) for b in ip_bytes)
        port_num = struct.unpack(">H", port_bytes)[0]
        peers += "{" + (f'"hostname":"{ip_str}","port":{port_num}') + "}";
    if peers.endswith(","):
        peers = peers[:-1]
    return ("[" + peers + "]") if peers else "[]"

# --- HTTP server ---
async def handle(request):
    tracker_param = request.query.get("tracker")
    info_hash_param = request.query.get("infohash")

    if not tracker_param or not info_hash_param:
        return web.Response(text="Missing tracker or infohash", status=400)

    # Parse tracker URL
    default_port = 1337
    try:
        parsed = urlparse(tracker_param if "://" in tracker_param else f"udp://{tracker_param}")
        host = parsed.hostname
        port = parsed.port or default_port
    except Exception:
        host = tracker_param
        port = default_port

    try:
        peers = await asyncio.to_thread(query_tracker, host, port, info_hash_param)
    except Exception as e:
        peers = f"Error: {e}"

    return web.Response(text=peers,content_type="application/json")

app = web.Application()
app.add_routes([web.get('/', handle)])

if __name__ == "__main__":
    web.run_app(app, port=8080)
