import base64
import json
import urllib.parse

INPUT = "ulinks.txt"
Q = urllib.parse.quote


def load_ulink(line):
    """ulink://install/?content=<base64 JSON>&format=json#name -> list of node dicts"""
    query = urllib.parse.parse_qs(urllib.parse.urlparse(line).query)
    c = query["content"][0].replace(" ", "+").replace("-", "+").replace("_", "/")
    c += "=" * (-len(c) % 4)
    data = json.loads(base64.b64decode(c).decode("utf-8"))
    return data if isinstance(data, list) else [data]


def qs(params):
    return urllib.parse.urlencode({k: v for k, v in params.items() if v not in ("", None)})


def transport_params(n):
    t = n.get("transport") or {}
    tt = t.get("type", "tcp")
    p = {"type": tt}
    if tt in ("ws", "httpupgrade"):
        headers = t.get("headers") or {}
        p["host"] = headers.get("Host") or headers.get("host") or t.get("host", "")
        p["path"] = t.get("path", "")
    elif tt == "grpc":
        p["serviceName"] = t.get("service_name", "")
    elif tt == "http":
        h = t.get("host", "")
        p["host"] = ",".join(h) if isinstance(h, list) else h
        p["path"] = t.get("path", "")
    return p


def tls_params(n):
    tls = n.get("tls") or {}
    if not tls.get("enabled"):
        return {"security": "none"}
    p = {"security": "tls", "sni": tls.get("server_name", "")}
    if tls.get("insecure"):
        p["allowInsecure"] = "1"
    if tls.get("alpn"):
        p["alpn"] = ",".join(tls["alpn"])
    fp = (tls.get("utls") or {}).get("fingerprint")
    if fp:
        p["fp"] = fp
    reality = tls.get("reality") or {}
    if reality.get("enabled"):
        p["security"] = "reality"
        p["pbk"] = reality.get("public_key", "")
        p["sid"] = reality.get("short_id", "")
    return p


def to_link(n):
    t = str(n.get("type", "")).lower()
    server, port = n.get("server"), n.get("server_port")
    if not server or not port:
        return None
    tag = Q(n.get("tag", t))

    if t == "hysteria":
        tls = n.get("tls") or {}
        p = {
            "protocol": "udp",
            "auth": n.get("auth_str", ""),
            "peer": tls.get("server_name", ""),
            "insecure": "1" if tls.get("insecure") else "0",
            "upmbps": n.get("up_mbps", ""),
            "downmbps": n.get("down_mbps", ""),
            "alpn": ",".join(tls.get("alpn", [])),
        }
        return "hysteria://{}:{}?{}#{}".format(server, port, qs(p), tag)

    if t == "hysteria2":
        tls = n.get("tls") or {}
        obfs = n.get("obfs") or {}
        p = {
            "sni": tls.get("server_name", ""),
            "insecure": "1" if tls.get("insecure") else "",
            "obfs": obfs.get("type", ""),
            "obfs-password": obfs.get("password", ""),
        }
        return "hysteria2://{}@{}:{}?{}#{}".format(Q(n.get("password", "")), server, port, qs(p), tag)

    if t == "vless":
        p = {"encryption": "none", "flow": n.get("flow", "")}
        p.update(tls_params(n))
        p.update(transport_params(n))
        return "vless://{}@{}:{}?{}#{}".format(n.get("uuid", ""), server, port, qs(p), tag)

    if t == "trojan":
        p = {}
        p.update(tls_params(n))
        p.update(transport_params(n))
        return "trojan://{}@{}:{}?{}#{}".format(Q(n.get("password", "")), server, port, qs(p), tag)

    if t in ("shadowsocks", "ss"):
        if not n.get("method") or not n.get("password"):
            return None
        user = base64.urlsafe_b64encode(
            (n["method"] + ":" + n["password"]).encode()
        ).decode().rstrip("=")
        return "ss://{}@{}:{}#{}".format(user, server, port, tag)

    return None


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

    # 2) share links + base64 subscription
    links, skipped = [], []
    for n in nodes:
        link = to_link(n)
        if link:
            links.append(link)
        else:
            skipped.append(n.get("type"))
    with open("nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(links) + ("\n" if links else ""))
    with open("subscription.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(links).encode("utf-8")).decode())

    print("nodes: {}, links: {}, not converted: {}".format(len(nodes), len(links), skipped))


if __name__ == "__main__":
    main()
