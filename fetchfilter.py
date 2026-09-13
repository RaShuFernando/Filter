import base64
import json
import os
import ssl
import urllib.parse
import urllib.request

# Source subscription URLs
SOURCE_URLS = [
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_base64_Sub.txt",
    "https://github.com/nikita29a/FreeProxyList/raw/refs/heads/main/mirror/1.txt",
    "https://github.com/nikita29a/FreeProxyList/raw/refs/heads/main/mirror/23.txt",
    "https://github.com/nikita29a/FreeProxyList/raw/refs/heads/main/mirror/3.txt",
    "https://github.com/nikita29a/FreeProxyList/raw/refs/heads/main/mirror/5.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
]

# Output files
OUTPUT_TXT = "zoom-teams-sub.txt"
OUTPUT_B64 = "zoom-teams-sub-b64.txt"

# Whitelisted root domains for Zoom/Teams packages (matches base domain and all subdomains)
ALLOWED_ROOT_DOMAINS = [
    "microsoft.com",
    "zoom.us",
    "office.com",
    "office365.com",
    "teams.microsoft.com",
    "azure.com",
    "azure.net",
    "aka.ms",
    "live.com",
    "skype.com",
]

ALLOWED_PORTS = {"443", "8443", 443, 8443}


def fetch_url_content(url, timeout=25):
    """Fetches raw subscription text from a given URL."""
    headers = {"User-Agent": "v2rayNG/1.8.5"}
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return ""


def extract_lines(raw_data):
    """Decodes Base64 subscriptions or splits plain text lines."""
    raw_data = raw_data.strip()
    if not raw_data:
        return []

    # Attempt Base64 decode first
    try:
        missing_padding = len(raw_data) % 4
        if missing_padding:
            raw_data += "=" * (4 - missing_padding)
        decoded = base64.b64decode(raw_data).decode("utf-8", errors="ignore")
        if any(proto in decoded for proto in ["vless://", "vmess://", "trojan://"]):
            return [line.strip() for line in decoded.splitlines() if line.strip()]
    except Exception:
        pass

    return [line.strip() for line in raw_data.splitlines() if line.strip()]


def matches_whitelist(domain):
    """Checks if a domain or hostname ends with any of our allowed root domains."""
    if not domain:
        return False
    domain = domain.lower().strip()
    for root in ALLOWED_ROOT_DOMAINS:
        if domain == root or domain.endswith("." + root):
            return True
    return False


def has_allowed_port(uri):
    """
    Parses the configuration to verify if the port matches the allowed ports.
    """
    try:
        if uri.startswith("vless://") or uri.startswith("trojan://"):
            parsed = urllib.parse.urlparse(uri)
            # parsed.port extracts the integer port from the netloc
            return parsed.port in ALLOWED_PORTS or str(parsed.port) in ALLOWED_PORTS

        elif uri.startswith("vmess://"):
            b64_str = uri[8:]
            missing_padding = len(b64_str) % 4
            if missing_padding:
                b64_str += "=" * (4 - missing_padding)
            json_data = json.loads(base64.b64decode(b64_str).decode("utf-8", errors="ignore"))
            
            port = json_data.get("port")
            return port in ALLOWED_PORTS or str(port) in ALLOWED_PORTS

    except Exception:
        return False
        
    return False


def is_target_config(uri):
    """
    Checks if a configuration natively uses a Microsoft or Zoom domain
    in its SNI, Host, or Server address.
    """
    try:
        # 1. Handle VLESS and Trojan
        if uri.startswith("vless://") or uri.startswith("trojan://"):
            parsed = urllib.parse.urlparse(uri)
            query_params = urllib.parse.parse_qs(parsed.query)

            # Check SNI, host header, or peer names
            sni = query_params.get("sni", [""])[0]
            host = query_params.get("host", [""])[0]
            peer = query_params.get("peer", [""])[0]
            server_name = query_params.get("serverName", [""])[0]

            domains_to_test = [sni, host, peer, server_name]

            if any(matches_whitelist(d) for d in domains_to_test):
                return True

        # 2. Handle VMess
        elif uri.startswith("vmess://"):
            b64_str = uri[8:]
            missing_padding = len(b64_str) % 4
            if missing_padding:
                b64_str += "=" * (4 - missing_padding)
            json_data = json.loads(base64.b64decode(b64_str).decode("utf-8", errors="ignore"))

            sni = json_data.get("sni", "")
            host = json_data.get("host", "")

            if matches_whitelist(sni) or matches_whitelist(host):
                return True

    except Exception:
        return False

    return False


def get_config_fingerprint(uri):
    """
    Generates a canonical string for a config by stripping out its remark/name.
    This allows deduplication of identical configs that only differ by name.
    """
    try:
        if uri.startswith("vless://") or uri.startswith("trojan://"):
            # Strip the remark (everything from '#' onwards)
            return uri.split("#")[0]
            
        elif uri.startswith("vmess://"):
            b64_str = uri[8:]
            missing_padding = len(b64_str) % 4
            if missing_padding:
                b64_str += "=" * (4 - missing_padding)
            json_data = json.loads(base64.b64decode(b64_str).decode("utf-8", errors="ignore"))

            # Remove the remark ('ps') key
            json_data.pop("ps", None)

            # Return a deterministic string representation of the JSON
            return "vmess://" + json.dumps(json_data, sort_keys=True)
            
    except Exception:
        pass
        
    return uri


def main():
    all_raw_lines = []

    print("[*] Fetching subscription pools...")
    for url in SOURCE_URLS:
        print(f" -> Downloading from: {url}")
        content = fetch_url_content(url)
        lines = extract_lines(content)
        print(f"    Extracted {len(lines)} configs.")
        all_raw_lines.extend(lines)

    # Name-agnostic deduplication
    unique_configs_pool = []
    seen_fingerprints = set()

    for line in all_raw_lines:
        fingerprint = get_config_fingerprint(line)
        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            unique_configs_pool.append(line)

    print(f"[*] Total unique configs to scan (ignoring name changes): {len(unique_configs_pool)}")

    matching_configs = []

    for line in unique_configs_pool:
        # Check both the port and the domain constraints
        if has_allowed_port(line) and is_target_config(line):
            matching_configs.append(line)

    print(f"[*] Found {len(matching_configs)} configs matching allowed ports and Microsoft/Zoom domains.")

    # Save output as plain text
    raw_content = "\n".join(matching_configs)
    with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
        f.write(raw_content)

    # Save output as standard Base64 subscription
    b64_content = base64.b64encode(raw_content.encode("utf-8")).decode("utf-8")
    with open(OUTPUT_B64, "w", encoding="utf-8") as f:
        f.write(b64_content)

    print(f"[*] Done! Saved to {OUTPUT_TXT} and {OUTPUT_B64}")


if __name__ == "__main__":
    main()
