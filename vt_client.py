import requests

def check_url(url, api_key):
    headers = {"x-apikey": api_key}
    scan_url = "https://www.virustotal.com/api/v3/urls"
    report_url = "https://www.virustotal.com/api/v3/analyses/"

    try:
        # Submit URL for analysis
        resp = requests.post(scan_url, headers=headers, data={"url": url})
        if resp.status_code != 200:
            print("Error submitting URL:", resp.text)
            return None

        analysis_id = resp.json()["data"]["id"]

        # Get the report
        report_resp = requests.get(report_url + analysis_id, headers=headers)
        if report_resp.status_code != 200:
            print("Error fetching report:", report_resp.text)
            return None

        data = report_resp.json()["data"]["attributes"]["stats"]
        data["last_analysis_date"] = report_resp.json()["data"]["attributes"].get("date")
        return data

    except Exception as e:
        print("Exception:", e)
        return None
