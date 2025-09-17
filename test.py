import requests
import json

url = "https://proportionate-dry-liquid.bsc.quiknode.pro/270e75d635b87ec6fbbec306a805f51acf4dc7f6/"

payload = json.dumps({
  "method": "eth_blockNumber",
  "params": [],
  "id": 1,
  "jsonrpc": "2.0"
})

headers = {
  'Content-Type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)