import base64
import concurrent.futures
import ipaddress
import os
import socket
import ssl
import urllib.parse
import urllib.request

# Source subscription URLs
SOURCE_URLS = [
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt",
]

# Output files
OUTPUT_TXT = "zoom-teams-sub.txt"
OUTPUT_B64 = "zoom-teams-sub-b64.txt"

# Rules for Zoom / Teams bypass
TARGET_SNI = "aka.ms"
ALLOWED_PORTS = {443, 8443}


def fetch_url_content(url, timeout=20):
    """Fetches raw text content from a given URL."""
    headers = {"User-Agent": "v2rayNG/1.8.5"}
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return ""


def get_cloudflare_networks():
    """Fetches Cloudflare's official IPv4 and IPv6 ranges."""
    print("[*] Downloading official Cloudflare IP ranges...")
    cf_ipv4 = fetch_url_content("https://www.cloudflare.com/ips-v4", timeout=10)
    cf_ipv6 = fetch_url_content("https://www.cloudflare.com/ips-v6", timeout=10)
    
    networks = []
    for cidr in cf_ipv4.splitlines() + cf_ipv6.splitlines():
        cidr = cidr.strip()
        if cidr:
            try:
                networks.append(ipaddress.ip_network(cidr))
            except ValueError:
                pass
    print(f"[*] Loaded {len(networks)} Cloudflare subnets.")
    return networks


def is_cloudflare_host(host, cf_networks):
    """Checks if a domain or IP belongs to Cloudflare."""
    # Step 1: Check if direct IP
    try:
        ip_obj = ipaddress.ip_address(host)
        return any(ip_obj in net for net in cf_networks)
    except ValueError:
        pass

    # Step 2: Resolve domain name
    try:
        socket.setdefaulttimeout(3)
        resolved_ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(resolved_ip)
        return any(ip_obj in net for net in cf_networks)
    except Exception:
        # If DNS fails, treat it as dead/bad node
        return True


def extract_lines(raw_data):
    """Handles both plain text lists and Base64-encoded subscription blocks."""
    lines = []
    raw_data = raw_data.strip()
    if not raw_data:
        return lines

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


def process_vless(uri, cf_networks):
    """Filters, injects Zoom/Teams SNI, and forces allowInsecure bypass."""
    try:
        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme.lower() != "vless":
            return None

        # 1. Verify port
        if parsed.port not in ALLOWED_PORTS:
            return None

        # 2. Check if host is Cloudflare (or unreachable domain)
        if not parsed.hostname or is_cloudflare_host(parsed.hostname, cf_networks):
            return None

        # 3. Must have TLS
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        security = params.get("security", [""])[0].lower()
        if security != "tls":
            return None

        # 4. Inject Zoom/Teams SNI & browser fingerprint
        params["sni"] = [TARGET_SNI]
        params["fp"] = ["chrome"]
        
        # 5. Skip certificate verification to stop the fingerprint prompt
        params["allowInsecure"] = ["1"]

        # Rebuild query string
        new_query_pairs = []
        for k, v_list in params.items():
            for v in v_list:
                new_query_pairs.append(f"{k}={urllib.parse.quote(v)}")
        new_query = "&".join(new_query_pairs)

        original_name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Node"
        new_fragment = urllib.parse.quote(f"[Zoom-Teams] {original_name}")

        new_parsed = parsed._replace(query=new_query, fragment=new_fragment)
        return urllib.parse.urlunparse(new_parsed)
    except Exception:
        return None


def main():
    cf_networks = get_cloudflare_networks()
    if not cf_networks:
        print("[!] Failed to fetch Cloudflare IP ranges. Aborting.")
        return

    all_raw_lines = []
    print("[*] Fetching subscription sources...")
    for url in SOURCE_URLS:
        print(f" -> Downloading from: {url}")
        content = fetch_url_content(url)
        lines = extract_lines(content)
        print(f"    Extracted {len(lines)} raw configs.")
        all_raw_lines.extend(lines)

    all_raw_lines = list(set(all_raw_lines))
    print(f"[*] Unique raw configs to process: {len(all_raw_lines)}")

    valid_configs = []
    seen = set()

    print("[*] Filtering nodes and verifying hosts (multi-threaded)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_uri = {
            executor.submit(process_vless, uri, cf_networks): uri 
            for uri in all_raw_lines if uri.startswith("vless://")
        }
        
        for future in concurrent.futures.as_completed(future_to_uri):
            processed = future.result()
            if processed:
                parsed = urllib.parse.urlparse(processed)
                unique_key = (parsed.hostname, parsed.port)
                if unique_key not in seen:
                    seen.add(unique_key)
                    valid_configs.append(processed)

    print(f"[*] Processing complete. Kept {len(valid_configs)} non-Cloudflare candidates.")

    # Save outputs
    raw_content = "\n".join(valid_configs)
    with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
        f.write(raw_content)

    b64_content = base64.b64encode(raw_content.encode("utf-8")).decode("utf-8")
    with open(OUTPUT_B64, "w", encoding="utf-8") as f:
        f.write(b64_content)

    print(f"[*] Saved files: {OUTPUT_TXT} and {OUTPUT_B64}")


if __name__ == "__main__":
    main()
