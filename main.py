import os
from vt_client import check_url
from dotenv import load_dotenv

def main():
    load_dotenv()
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("❌ VIRUSTOTAL_API_KEY not set. Please add it to your .env file.")
        return

    print("🔍 URL Malware Sandbox (VirusTotal API)")
    url = input("Enter a URL to scan: ")
    result = check_url(url, api_key)

    if result:
        print(f"\n✅ Scan completed for: {url}")
        print(f"🧩 Malicious detections: {result.get('malicious', 'N/A')}")
        print(f"🧪 Suspicious detections: {result.get('suspicious', 'N/A')}")
        print(f"🔎 Harmless detections: {result.get('harmless', 'N/A')}")
        print(f"🕒 Last Analysis Date: {result.get('last_analysis_date', 'N/A')}")
    else:
        print("⚠️ Could not analyze the URL or API error.")

if __name__ == "__main__":
    main()
