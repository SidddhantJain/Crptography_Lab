from typing import Tuple

def simple_hash(s: str) -> str:
    h = 5381
    for c in s.encode('utf-8'):
        h = ((h << 5) + h) + c  # h*33 + c
        h &= 0xFFFFFFFFFFFFFFFF  # keep it bounded (optional)
    return f"{h & 0xFFFFFFFF:08x}"


def sender(msg: str) -> tuple[str, str]:
    return msg, simple_hash(msg)


def receiver_check(msg: str, sent_digest: str) -> bool:
    my_digest = simple_hash(msg)
    print(f"[RECEIVER] Recomputed digest: {my_digest}")
    return my_digest == sent_digest


def main() -> None:
    message = input("Enter message to send: ")

    sent_msg, sent_dig = sender(message)
    print(f"\n[SENDER] Message: {sent_msg}")
    print(f"[SENDER] Simple-hash: {sent_dig}\n")

    print("[NETWORK] Delivering message (no tampering)...")
    ok = receiver_check(sent_msg, sent_dig)
    print("Result: Hashes match : integrity OK.\n" if ok else "Result: Hash mismatch!\n")

    print("Demonstrating tampering (flip first byte if exists)...")
    if sent_msg:
        tampered = chr(ord(sent_msg[0]) ^ 0x01) + sent_msg[1:]
    else:
        tampered = sent_msg
    print(f"[NETWORK] Tampered message: {tampered}")
    ok2 = receiver_check(tampered, sent_dig)
    print("Result: Hashes match (unexpected)." if ok2 else "Result: Hash mismatch : tampering detected.")


if __name__ == "__main__":
    main()
