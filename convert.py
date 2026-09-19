import base64
import json
import urllib.parse

INPUT_FILE = "ulinks.txt"
OUTPUT_FILE = "nodes.txt"


def decode_base64_auto(text):
    text = text.strip()

    # Base64 URL-safe
    text += "=" * (-len(text) % 4)

    try:
        return base64.urlsafe_b64decode(text).decode("utf-8")
    except Exception:
        return None


def parse_ulink(line):
    line = line.strip()

    if not line.startswith("ulink://"):
        return None

    # 取出 ?content= 后面的内容
    try:
        parsed = urllib.parse.urlparse(line)
        query = urllib.parse.parse_qs(parsed.query)

        content_list = query.get("content")
        if not content_list:
            return None

        decoded = decode_base64_auto(content_list[0])

        if not decoded:
            return None

        return json.loads(decoded)

    except Exception as e:
        print("解析失败:", e)
        return None


def encode_base64(text):
    return base64.urlsafe_b64encode(
        text.encode("utf-8")
    ).decode("utf-8").rstrip("=")


def convert_node(node):
    if not isinstance(node, dict):
        return None

    node_type = str(node.get("type", "")).lower()

    # Shadowsocks
    if node_type in ("shadowsocks", "ss"):
        server = node.get("server", "")
        port = node.get("server_port", "")
        method = node.get("method", "")
        password = node.get("password", "")
        tag = node.get("tag", "SS")

        if not server or not port or not method or not password:
            return None

        userinfo = encode_base64(
            method + ":" + password
        )

        return "ss://{}@{}:{}#{}".format(
            userinfo,
            server,
            port,
            urllib.parse.quote(str(tag))
        )

    # VLESS
    if node_type == "vless":
        uuid = node.get("uuid", "")
        server = node.get("server", "")
        port = node.get("server_port", "")
        tag = node.get("tag", "VLESS")

        if not uuid or not server or not port:
            return None

        params = []

        tls = node.get("tls")
        if isinstance(tls, dict):
            if tls.get("enabled"):
                params.append("security=tls")

            server_name = tls.get("server_name")
            if server_name:
                params.append(
                    "sni=" + urllib.parse.quote(str(server_name))
                )

        flow = node.get("flow")
        if flow:
            params.append(
                "flow=" + urllib.parse.quote(str(flow))
            )

        query = "&".join(params)

        result = "vless://{}@{}:{}".format(
            uuid,
            server,
            port
        )

        if query:
            result += "?" + query

        result += "#" + urllib.parse.quote(str(tag))

        return result

    # Trojan
    if node_type == "trojan":
        password = node.get("password", "")
        server = node.get("server", "")
        port = node.get("server_port", "")
        tag = node.get("tag", "Trojan")

        if not password or not server or not port:
            return None

        result = "trojan://{}@{}:{}".format(
            urllib.parse.quote(str(password)),
            server,
            port
        )

        tls = node.get("tls")

        params = []

        if isinstance(tls, dict):
            server_name = tls.get("server_name")

            if server_name:
                params.append(
                    "sni=" + urllib.parse.quote(str(server_name))
                )

        if params:
            result += "?" + "&".join(params)

        result += "#" + urllib.parse.quote(str(tag))

        return result

    return None


def main():
    nodes = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):

            line = line.strip()

            if not line:
                continue

            data = parse_ulink(line)

            if data is None:
                print("第 {} 行解析失败".format(line_number))
                continue

            # Karing / sing-box 数据有可能是数组
            if isinstance(data, list):
                node_list = data
            else:
                node_list = [data]

            for node in node_list:
                result = convert_node(node)

                if result:
                    nodes.append(result)
                else:
                    print(
                        "第 {} 行存在暂未支持的节点类型: {}".format(
                            line_number,
                            node.get("type", "unknown")
                            if isinstance(node, dict)
                            else "unknown"
                        )
                    )

    # 去重
    nodes = list(dict.fromkeys(nodes))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for node in nodes:
            f.write(node + "\n")

    print("转换完成，共生成 {} 个节点".format(len(nodes)))


if __name__ == "__main__":
    main()
