import os
import sys
import time
import requests
import logging
from dotenv import load_dotenv
from supabase import create_client
from eth_utils import is_checksum_address, to_checksum_address

# Load env vars
load_dotenv()

# === Supabase ===
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ROLE_KEY = os.getenv("SUPABASE_ROLE_KEY")
if not SUPABASE_URL or not SUPABASE_ROLE_KEY:
    raise ValueError("❌ Missing SUPABASE_URL or SUPABASE_ROLE_KEY in env")

supabase = create_client(SUPABASE_URL, SUPABASE_ROLE_KEY)

# === GetBlock BSC ===
GETBLOCK_BSC_URL = os.getenv("GETBLOCK_BSC_URL")
USDC_CONTRACT = os.getenv("USDC_CONTRACT", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d")  # USDC BEP20
PAGE_LIMIT = int(os.getenv("PAGE_LIMIT", "100"))
WATCH_INTERVAL = int(os.getenv("WATCH_INTERVAL", "5"))
USERS_REFRESH_INTERVAL = int(os.getenv("USERS_REFRESH_INTERVAL", "60"))

# === Logging setup ===
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(message)s"))
if hasattr(handler.stream, "reconfigure"):
    handler.stream.reconfigure(encoding="utf-8")

logging.basicConfig(handlers=[handler], level=logging.INFO)

deposit_logger = logging.getLogger("usdc_deposits")
stats_logger = logging.getLogger("usdc_stats")

deposit_handler = logging.FileHandler("usdc_deposits.log", encoding="utf-8")
stats_handler = logging.FileHandler("usdc_stats.log", encoding="utf-8")

deposit_logger.addHandler(deposit_handler)
stats_logger.addHandler(stats_handler)

deposit_logger.setLevel(logging.INFO)
stats_logger.setLevel(logging.INFO)

# === Global storage ===
bsc_addresses = {}  # address -> user_id
invalid_addresses = set()
last_seen_txids = set()

print("✅ USDC BEP20 watcher started")

# stats counters
events_in_minute = 0
minute_start = time.time()
last_user_refresh = 0
last_block = None


def fetch_addresses():
    """Fetch all user wallet addresses from supabase (bsc_address field)"""
    global bsc_addresses, invalid_addresses
    res = supabase.table("users").select("id, bsc_address").execute()
    if not res.data:
        return

    new_map = dict(bsc_addresses)

    for row in res.data:
        addr = row.get("bsc_address")
        uid = row.get("id", -1)
        if not addr:
            continue
        try:
            checksum_addr = to_checksum_address(addr)
            new_map[checksum_addr] = uid
        except Exception:
            if addr not in invalid_addresses:
                print(f"⚠️ Skipping invalid BSC address: {addr}")
                invalid_addresses.add(addr)

    added = set(new_map.keys()) - set(bsc_addresses.keys())
    if added:
        for addr in added:
            print(f"➕ New valid BSC address added: {addr} (user_id={new_map[addr]})")

    bsc_addresses = new_map


def deposit_exists(txid: str) -> bool:
    """Check if txid already inserted"""
    try:
        res = supabase.table("deposits").select("id").eq("status", "confirmed").eq("txid", txid).execute()
        return bool(res.data)
    except Exception as e:
        print("❌ Error checking txid:", e)
        return False


def watch_usdc():
    """Poll latest logs for USDC transfers"""
    global last_seen_txids, events_in_minute, last_block

    # ERC20 Transfer event signature
    transfer_sig = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

    # fetch latest block
    latest = requests.post(GETBLOCK_BSC_URL, json={"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}).json()
    latest_block = int(latest["result"], 16)

    if last_block is None:
        last_block = latest_block - 3  # small back offset

    # query logs
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getLogs",
        "params": [{
            "fromBlock": hex(last_block),
            "toBlock": hex(latest_block),
            "address": USDC_CONTRACT,
            "topics": [transfer_sig]
        }],
        "id": 1
    }
    r = requests.post(GETBLOCK_BSC_URL, json=payload).json()
    logs = r.get("result", [])

    for log in logs:
        txid = log["transactionHash"]
        if txid in last_seen_txids:
            continue

        topics = log["topics"]
        from_addr = "0x" + topics[1][-40:]
        to_addr = "0x" + topics[2][-40:]
        amount = int(log["data"], 16) / 1e18  # USDC decimals on BSC = 18

        if to_addr in bsc_addresses:
            uid = bsc_addresses[to_addr]
            msg = f"💰 USDC deposit: {amount} from {from_addr} → {to_addr} (user_id={uid}, tx={txid})"
            print(msg)
            deposit_logger.info(msg)

            if uid != -1 and not deposit_exists(txid):
                try:
                    supabase.table("deposits").insert({
                        "user_id": uid,
                        "amount": amount,
                        "status": "confirmed",
                        "txid": txid
                    }).execute()
                    deposit_logger.info(f"📝 Saved deposit for user_id={uid}, amount={amount}, tx={txid}")
                except Exception as e:
                    deposit_logger.error(f"❌ Error inserting deposit: {e}")

        last_seen_txids.add(txid)
        events_in_minute += 1

    last_block = latest_block + 1


def run_usdc_watcher():
    global last_user_refresh, minute_start, events_in_minute

    while True:
        try:
            now = time.time()
            if now - last_user_refresh >= USERS_REFRESH_INTERVAL:
                fetch_addresses()
                last_user_refresh = now

            watch_usdc()

            if now - minute_start >= 60:
                eps = events_in_minute / 60
                stats_msg = f"📊 USDC Stats: {events_in_minute} events in last minute (~{eps:.1f}/sec)"
                stats_logger.info(stats_msg)
                print(stats_msg)
                events_in_minute = 0
                minute_start = now

        except Exception as e:
            print("Error:", e)

        time.sleep(WATCH_INTERVAL)