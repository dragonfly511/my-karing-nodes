import base64
import json
import urllib.parse

INPUT = "ulinks.txt"


def load_ulink(line):
    """ulink://install/?content=<base64 JSON>&format=json#name -> list of node dicts"""
    query = urllib.parse.parse_qs(urllib.parse.urlparse(line).query)
    c = query["content"][0].replace(" ", "+").replace("-", "+").replace("_", "/")
    c += "=" * (-len(c) % 4)
    data = json.loads(base64.b64decode(c).decode("utf-8"))
    return data if isinstance(data, list) else [data]


def hysteria_link(n):
    tls = n.get("tls") or {}
    params = {
        "protocol": "udp",
        "auth": n.get("auth_str", ""),
        "peer": tls.get("server_name", ""),
        "insecure": "1" if tls.get("insecure") else "0",
        "upmbps": n.get("up_mbps", ""),
        "downmbps": n.get("down_mbps", ""),
        "alpn": ",".join(tls.get("alpn", [])),
    }
    q = urllib.parse.urlencode({k: v for k, v in params.items() if v != ""})
    tag = urllib.parse.quote(n.get("tag", "hysteria"))
    return "hysteria://{}:{}?{}#{}".format(n["server"], n["server_port"], q, tag)


def main():
    nodes, seen = [], set()
    with open(INPUT, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line.startswith("ulink://"):
                continue
            try:
                items = load_ulink(line)
            except Exception as e:
                print("line {} failed: {}".format(i, e))
                continue
            for n in items:
                key = json.dumps({k: v for k, v in n.items() if k != "tag"}, sort_keys=True)
                if key not in seen:
                    seen.add(key)
                    nodes.append(n)

    # 1) lossless: all node JSON merged into one array
    with open("subscription.json", "w", encoding="utf-8") as f:
        json.dump(nodes, f, ensure_ascii=False, indent=1)

    # 2) share links (currently only hysteria v1)
    links = [hysteria_link(n) for n in nodes if n.get("type") == "hysteria"]
    skipped = [n.get("type") for n in nodes if n.get("type") != "hysteria"]
    with open("nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(links) + ("\n" if links else ""))
    with open("subscription.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(links).encode("utf-8")).decode())

    print("nodes: {}, links: {}, not converted to links: {}".format(len(nodes), len(links), skipped))


if __name__ == "__main__":
    main()
