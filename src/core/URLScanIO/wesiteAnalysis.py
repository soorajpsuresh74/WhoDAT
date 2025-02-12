import time
import requests
import config

headers = {
    'API-Key': config.MySecret.URLSCANIO_API_KEY,
    'Content-Type': 'application/json'
}


def scan_website(website):
    """Initiates a scan for a given website and returns the scan ID."""
    payload = {'url': website}
    try:
        response = requests.post(config.MySecret.URLSCANIO_ENDPOINT, headers=headers, json=payload)

        if response.status_code == 200:
            data = response.json()
            scan_id = data['uuid']
            print(f"Scan initiated for {website}. Scan ID: {scan_id}")
            return scan_id
        else:
            print(f"Failed to scan {website}: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"Error scanning {website}: {str(e)}")
        return None


def get_scan_result(scan_id, max_wait_time=60):
    """
    Polls for scan completion and retrieves the scan result.

    Args:
        scan_id (str): The unique ID of the scan.
        max_wait_time (int): Maximum time (in seconds) to wait for scan completion.

    Returns:
        dict: Scan results if successful, None otherwise.
    """
    start_time = time.time()
    wait_time = 5  # Initial wait time

    while True:
        elapsed_time = time.time() - start_time

        if elapsed_time > max_wait_time:
            print(f"Timeout: Scan {scan_id} did not complete within {max_wait_time} seconds.")
            return None

        response = requests.get(f'https://urlscan.io/api/v1/result/{scan_id}/', headers=headers)

        if response.status_code == 200:
            result = response.json()
            print(f"Scan result for {scan_id} retrieved successfully.")
            return result
        elif response.status_code == 404:
            print(f"Scan {scan_id} is not finished yet. Retrying in {wait_time} seconds...")
        elif response.status_code == 429:
            print("Rate limited by API. Waiting before retrying...")
            time.sleep(10)
        else:
            print(f"Unexpected error while fetching scan result: {response.status_code}, {response.text}")
            return None

        time.sleep(wait_time)  # Wait before retrying
        wait_time = min(wait_time * 2, 30)  # Exponential backoff, max 30s


def check_malicious_status(website):
    """
    Checks if the given website is flagged as malicious using URLScan.io search API.

    Args:
        website (str): The website URL to check.

    Returns:
        str: "Malicious" if flagged, "Safe" otherwise.
    """
    try:
        response = requests.get(f'https://urlscan.io/api/v1/search/?q=domain:{website}', headers=headers)
        if response.status_code == 200:
            data = response.json()
            for result in data.get('results', []):
                if result.get('verdicts', {}).get('malicious', {}).get('overall', False):
                    return "Malicious"
            return "Safe"
        else:
            print(f"Failed to check malicious status: {response.status_code}, {response.text}")
            return "Unknown"
    except Exception as e:
        print(f"Error checking malicious status for {website}: {str(e)}")
        return "Error"


def website_analysis(website_input):
    results = []
    for website in website_input:
        print(f"\nAnalyzing {website}...")

        # Check if the website is malicious
        status = check_malicious_status(website)
        print(f"Malicious Status: {status}")

        # Scan website and get results
        scan_id = scan_website(website)

        if scan_id:
            scan_result = get_scan_result(scan_id)
            screenshot_url = scan_result.get("task", {}).get("screenshotURL") if scan_result else "Not Available"

            results.append({
                'website': website,
                'malicious_status': status,
                'scan_result': scan_result,
                'screenshot': screenshot_url
            })

            print(f"Screenshot URL: {screenshot_url}")

    return results
