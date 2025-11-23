#!/usr/bin/env python3
import argparse, base64, json, ssl, sys, urllib.parse
from urllib import request, error

def _tls_context(verify: bool):
    """Return an SSL context based on whether we verify TLS certs."""
    if verify:
        return None  # default verification
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _join_remote(remote_dir: str, filename: str) -> str:
    """Join folder + filename to a clean relative path (no leading slash)."""
    remote_dir = (remote_dir or "").strip().strip("/")
    return f"{remote_dir}/{filename}".lstrip("/")

def _quote_path_keep_slashes(p: str) -> str:
    """URL-quote a WebDAV path but keep path separators (/)."""
    return urllib.parse.quote(p, safe="/")

def put_file(base_url, user, pwd, local_path, remote_rel_path, verify_tls=False):
    """
    Upload a file via WebDAV:
      PUT {base}/remote.php/dav/files/{user}/{remote_rel_path}
    """
    dav_url = (
        f"{base_url}/remote.php/dav/files/"
        f"{urllib.parse.quote(user)}"  # user itself (no slashes)
        f"/{_quote_path_keep_slashes(remote_rel_path)}"
    )
    with open(local_path, "rb") as f:
        data = f.read()

    req = request.Request(dav_url, data=data, method="PUT")
    b64 = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    req.add_header("Authorization", f"Basic {b64}")
    req.add_header("Content-Type", "application/octet-stream")

    with request.urlopen(req, context=_tls_context(verify_tls)) as resp:
        if resp.status not in (201, 204):
            raise RuntimeError(f"UPLOAD HTTP {resp.status}")

def create_public_link_token(base_url, user, pwd, rel_path, verify_tls=False) -> str:
    """
    Create a public link via OCS; return its token.
    """
    if not rel_path.startswith("/"):
        rel_path = "/" + rel_path
    share_url = f"{base_url}/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json"

    payload = urllib.parse.urlencode({
        "path": rel_path,
        "shareType": "3",      # public link
        "permissions": "1"     # read-only
    }).encode()

    req = request.Request(share_url, data=payload, method="POST")
    b64 = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    req.add_header("Authorization", f"Basic {b64}")
    req.add_header("OCS-APIRequest", "true")
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    with request.urlopen(req, context=_tls_context(verify_tls)) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        js = json.loads(body)
        meta = js.get("ocs", {}).get("meta", {})
        code = str(meta.get("statuscode", ""))
        if code not in ("100", "200"):
            raise RuntimeError(f"OCS failed (statuscode {code}): {meta.get('message','')}")
        data = js.get("ocs", {}).get("data", {}) or {}
        token = data.get("token")
        if not token:
            link = data.get("url") or data.get("link") or ""
            parts = link.rstrip("/").split("/")
            token = parts[-1] if parts else ""
        if not token:
            raise RuntimeError("OCS response missing share token")
        return token

def build_direct_download_url(base_url: str, token: str, remote_dir: str, filename: str) -> str:
    """
    Build a URL that forces download:
      https://host/s/<TOKEN>/download?path=/FOLDER&files=FILENAME
    """
    clean_dir = (remote_dir or "").strip().strip("/")
    path_q = "/" if clean_dir == "" else f"/{clean_dir}"
    return (
        f"{base_url}/s/{token}/download"
        f"?path={urllib.parse.quote(path_q)}"
        f"&files={urllib.parse.quote(filename)}"
    )

def main():
    # Hardcoded parameters
    base_url = "https://nextcloud.secureskies.local"
    user = "jruecker"
    password = "BlueFishSea2883!"
    local_path = "/tmp/nmap_transfer/dphelper_v2.4_test_build"
    remote_folder = "Documents"
    filename = "dphelper_v2.4_test_build"
    verify_tls = False

    # Commented out argparse code for future use
    # p = argparse.ArgumentParser(description="Upload to Nextcloud and print a direct-download URL")
    # p.add_argument("--url", required=True, help="Base URL, e.g. https://nextcloud.secureskies.local")
    # p.add_argument("--user", required=True, help="Nextcloud username")
    # p.add_argument("--password", required=True, help="Nextcloud password (or app password)")
    # p.add_argument("--local", required=True, help="Path to local file")
    # p.add_argument("--remote", required=True, help="Remote folder (e.g., 'Documents' or '/')")
    # p.add_argument("--filename", required=True, help="Destination filename (e.g., 'loot2.txt')")
    # p.add_argument("--secure", action="store_true",
    #                help="Verify TLS certificates (default: disabled)")
    # args = p.parse_args()
    # 
    # # Default: insecure (no verification). If --secure is given, enable verification.
    # verify_tls = args.secure
    # 
    # remote_rel = _join_remote(args.remote, args.filename)

    remote_rel = _join_remote(remote_folder, filename)
    try:
        put_file(base_url, user, password, local_path, remote_rel, verify_tls=verify_tls)
        token = create_public_link_token(base_url, user, password, remote_rel, verify_tls=verify_tls)
        direct = build_direct_download_url(base_url, token, remote_folder, filename)
        print(direct)  # <-- print ONLY the direct-download URL
    except error.HTTPError as e:
        sys.stderr.write(f"HTTP {e.code}\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"{e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()


