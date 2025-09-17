import os
import sys
import time
import requests
import logging
from dotenv import load_dotenv
from supabase import create_client
from tronpy.keys import is_base58check_address, to_base58check_address

# Load env vars
load_dotenv()

# === Supabase ===
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ROLE_KEY = os.getenv("SUPABASE_ROLE_KEY")
if not SUPABASE_URL or not SUPABASE_ROLE_KEY:
    raise ValueError("❌ Missing SUPABASE_URL or SUPABASE_ROLE_KEY in env")

supabase = create_client(SUPABASE_URL, SUPABASE_ROLE_KEY)

# === TronGrid ===
API_KEY = os.getenv("TRONGRID_API_KEY", "")
USDT_CONTRACT = os.getenv("USDT_CONTRACT", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")

MAX_PAGES = int(os.getenv("MAX_PAGES", "8"))
PAGE_LIMIT = int(os.getenv("PAGE_LIMIT", "200"))  # TronGrid max is 200
WATCH_INTERVAL = int(os.getenv("WATCH_INTERVAL", "2"))
USERS_REFRESH_INTERVAL = int(os.getenv("USERS_REFRESH_INTERVAL", "60"))

url = f"https://api.trongrid.io/v1/contracts/{USDT_CONTRACT}/events"
headers = {"TRON-PRO-API-KEY": API_KEY}

# === Logging setup ===
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(message)s"))

# Force stdout to UTF-8 if supported (Python 3.7+)
if hasattr(handler.stream, "reconfigure"):
    handler.stream.reconfigure(encoding="utf-8")

logging.basicConfig(handlers=[handler], level=logging.INFO)

# Two separate loggers
deposit_logger = logging.getLogger("deposits")
stats_logger = logging.getLogger("stats")

# File handlers with UTF-8 encoding
deposit_handler = logging.FileHandler("usdt_deposits.log", encoding="utf-8")
stats_handler = logging.FileHandler("usdt_stats.log", encoding="utf-8")

deposit_logger.addHandler(deposit_handler)
stats_logger.addHandler(stats_handler)

deposit_logger.setLevel(logging.INFO)
stats_logger.setLevel(logging.INFO)

# === Global storage ===
tron_addresses = {}       # address -> user_id
invalid_addresses = set()
last_seen_txids = set()

# preload startup addresses with fake user_id = -1
preloaded = [
    "TSYsPETKdGXR1nLZVBwsrajDcb2YwtrbEC",
    "TSRWoob6nQVS9H14VWK5Mb7cCwMgyZtE77"
]
for addr in preloaded:
    tron_addresses[addr] = -1

print(f"✅ Preloaded startup addresses: {tron_addresses}")

# start from "now"
last_ts = int(time.time() * 1000)

# stats counters
events_in_minute = 0
minute_start = time.time()

# timers
last_user_refresh = 0


def fetch_addresses():
    """Fetch all tron_address + id from users table"""
    global tron_addresses, invalid_addresses
    res = supabase.table("users").select("id, tron_address").execute()
    if not res.data:
        return

    new_map = dict(tron_addresses)  # keep preloaded

    for row in res.data:
        addr = row.get("tron_address")
        uid = row.get("id", -1)
        if not addr:
            continue

        if is_base58check_address(addr):
            new_map[addr] = uid
        else:
            if addr not in invalid_addresses:
                print(f"⚠️ Skipping invalid address: {addr}")
                invalid_addresses.add(addr)

    added = set(new_map.keys()) - set(tron_addresses.keys())
    if added:
        for addr in added:
            print(f"➕ New valid address added: {addr} (user_id={new_map[addr]})")

    tron_addresses = new_map


def deposit_exists(txid: str) -> bool:
    """Check if this txid was already inserted in deposits table"""
    try:
        res = supabase.table("deposits").select("id").eq("status", "confirmed").eq("txid", txid).execute()
        return bool(res.data)
    except Exception as e:
        print("❌ Error checking txid:", e)
        return False


def watch_usdt():
    """Fetch USDT Transfer events and check against user wallets"""
    global last_ts, last_seen_txids, events_in_minute

    params = {
        "event_name": "Transfer",
        "min_block_timestamp": last_ts,
        "limit": PAGE_LIMIT,
    }

    fingerprint = None
    page_count = 0
    newest_ts = last_ts

    while page_count < MAX_PAGES:
        if fingerprint:
            params["fingerprint"] = fingerprint

        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()

        events = data.get("data", [])
        if not events:
            break

        for event in events:
            txid = event["transaction_id"]
            ts = event["block_timestamp"]

            if txid in last_seen_txids:
                continue

            to_addr = to_base58check_address(bytes.fromhex(event["result"]["to"][2:]))
            from_addr = to_base58check_address(bytes.fromhex(event["result"]["from"][2:]))
            amount = int(event["result"]["value"]) / 1_000_000

            if to_addr in tron_addresses:
                uid = tron_addresses.get(to_addr, -1)

                msg = f"💰 USDT deposit: {amount} from {from_addr} → {to_addr} (user_id={uid}, tx={txid})"
                print(msg)
                deposit_logger.info(msg)

                # ✅ insert into deposits table if user_id is real and tx not yet saved
                if uid != -1 and not deposit_exists(txid):
                    try:
                        supabase.table("deposits").insert({
                            "user_id": uid,
                            "amount": amount,
                            "status": "confirmed",
                            "txid": txid,  # <-- add txid column to prevent duplicates
                        }).execute()
                        deposit_logger.info(f"📝 Saved deposit for user_id={uid}, amount={amount}, tx={txid}")
                        print(f"📝 Saved deposit for user_id={uid}, amount={amount}, tx={txid}")
                    except Exception as e:
                        deposit_logger.error(f"❌ Error inserting deposit: {e}")

            newest_ts = max(newest_ts, ts)
            last_seen_txids.add(txid)
            events_in_minute += 1

        fingerprint = data.get("meta", {}).get("fingerprint")
        page_count += 1

        if not fingerprint:
            break

    if page_count == MAX_PAGES and fingerprint:
        print(f"⚠️ Hit page cap ({MAX_PAGES}) for this cycle, will continue next loop...")

    last_ts = newest_ts + 1

    if len(last_seen_txids) > 500:
        last_seen_txids = set(list(last_seen_txids)[-500:])


def run_usdt_watcher():
    """Main loop: refresh user wallets & watch USDT deposits"""
    global last_user_refresh, minute_start, events_in_minute

    while True:
        try:
            now = time.time()

            if now - last_user_refresh >= USERS_REFRESH_INTERVAL:
                fetch_addresses()
                last_user_refresh = now

            watch_usdt()

            if now - minute_start >= 60:
                eps = events_in_minute / 60
                stats_msg = f"📊 Stats: {events_in_minute} events in last minute (~{eps:.1f}/sec)"
                stats_logger.info(stats_msg)
                events_in_minute = 0
                minute_start = now

        except Exception as e:
            print("Error:", e)

        time.sleep(WATCH_INTERVAL)