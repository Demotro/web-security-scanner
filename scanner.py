import argparse
import json
import requests


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


def check_https(url):
    return url.startswith("https://")


def scan_url(url):
    result = {
        "target": url,
        "status_code": None,
        "https_enabled": check_https(url),
        "security_headers": {},
        "security_score": 0,
        "max_score": len(SECURITY_HEADERS) + 1,
        "error": None
    }

    try:
        response = requests.get(url, timeout=5)

        result["status_code"] = response.status_code

        if result["https_enabled"]:
            result["security_score"] += 1

        for header in SECURITY_HEADERS:
            is_present = header in response.headers

            result["security_headers"][header] = {
                "present": is_present,
                "value": response.headers.get(header)
            }

            if is_present:
                result["security_score"] += 1

    except requests.exceptions.MissingSchema:
        result["error"] = "Invalid URL format. Use format like: https://example.com"

    except requests.exceptions.ConnectionError:
        result["error"] = "Could not connect to the target."

    except requests.exceptions.Timeout:
        result["error"] = "Request timed out."

    except requests.exceptions.RequestException as error:
        result["error"] = str(error)

    return result


def print_report(result):
    print("Web Security Scanner CLI")
    print("------------------------")
    print("Target:", result["target"])

    if result["error"]:
        print("[ERROR]", result["error"])
        return

    print("Status code:", result["status_code"])

    if result["https_enabled"]:
        print("[OK] HTTPS is enabled")
    else:
        print("[WARN] HTTPS is not used")

    print()
    print("Security headers:")

    for header, data in result["security_headers"].items():
        if data["present"]:
            print(f"[OK] {header} is present")
        else:
            print(f"[WARN] {header} is missing")

    print()
    print(f"Security score: {result['security_score']}/{result['max_score']}")


def save_json_report(result, filename):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    print()
    print(f"[INFO] JSON report saved to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Basic web security scanner"
    )

    parser.add_argument(
        "url",
        help="Target URL, for example https://example.com"
    )

    parser.add_argument(
        "--json",
        help="Save scan result to a JSON file, for example report.json"
    )

    args = parser.parse_args()

    result = scan_url(args.url)
    print_report(result)

    if args.json:
        save_json_report(result, args.json)


if __name__ == "__main__":
    main()