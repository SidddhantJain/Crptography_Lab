import json
import socket
import hashlib
from contextlib import closing


# --- SHA-1 helper --------------------------------------------------------------
def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode('utf-8')).hexdigest()


# --- Simple line-based protocol (JSON per line) --------------------------------
def recv_json_line(conn: socket.socket, max_bytes: int = 1_000_000) -> dict:
    data = bytearray()
    while b"\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > max_bytes:
            raise ValueError("Incoming message too large")
    line = data.split(b"\n", 1)[0]
    return json.loads(line.decode('utf-8'))


def send_json_line(conn: socket.socket, obj: dict) -> None:
    payload = (json.dumps(obj) + "\n").encode('utf-8')
    conn.sendall(payload)


# --- Server (Terminal 1) -------------------------------------------------------
def run_server(host: str = "127.0.0.1", port: int = 5000) -> None:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        print(f"[SERVER] Listening on {host}:{port} ...")
        conn, addr = s.accept()
        with closing(conn):
            print(f"[SERVER] Connected by {addr}")
            pkt = recv_json_line(conn)
            msg = pkt.get('msg', '')
            dig = pkt.get('sha1', '')
            my = sha1_hex(msg)
            ok = (my == dig)
            print(f"[SERVER] Received: {msg}")
            print(f"[SERVER] SHA1 from client: {dig}")
            print(f"[SERVER] SHA1 recomputed : {my}")
            print("[SERVER] Integrity: PASS" if ok else "[SERVER] Integrity: FAIL")
            send_json_line(conn, {"ok": ok})


# --- Client (Terminal 2) -------------------------------------------------------
def run_client(host: str, port: int, message: str) -> None:
    d = sha1_hex(message)
    pkt = {"msg": message, "sha1": d}
    with closing(socket.create_connection((host, port), timeout=10)) as c:
        send_json_line(c, pkt)
        print(f"[CLIENT] Sent message + SHA1: {d}")
        try:
            resp = recv_json_line(c)
            print(f"[CLIENT] Server response: {resp}")
        except Exception:
            print("[CLIENT] No response from server (connection closed)")


def main() -> None:
    print("=== Assignment 5: SHA-1 Integrity over TCP ===")
    role = input("Run as (s)erver or (c)lient? ").strip().lower()[:1]
    host = input("Host [127.0.0.1]: ").strip() or "127.0.0.1"
    try:
        port = int(input("Port [5000]: ").strip() or "5000")
    except ValueError:
        print("Invalid port"); return

    if role == 's':
        run_server(host, port)
    elif role == 'c':
        msg = input("Enter message to send: ")
        run_client(host, port, msg)
    else:
        print("Choose 's' for server or 'c' for client.")


if __name__ == "__main__":
    main()
