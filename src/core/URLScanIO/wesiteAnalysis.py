import time

import requests

import config

headers = {
    'API-Key':config.MySecret.URLSCANIO_API_KEY,
    'Content-Type':'application/json'
}


def scan_website(website):
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

def get_scan_result(scan_id):
    try:
        time.sleep(5)
        response = requests.get(f'https://urlscan.io/api/v1/result/{scan_id}/', headers=headers)

        if response.status_code == 200:
            result = response.json()
            print(f"Scan result for {scan_id}:")
            return result
        else:
            print(f"Failed to get result for scan {scan_id}: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"Error fetching scan result for {scan_id}: {str(e)}")
        return None

def website_analysis(website_input):
    results = []
    for website in website_input:
        scan_id = scan_website(website)

        if scan_id:
            scan_result = get_scan_result(scan_id)
            results.append({
                'website': website,
                'scan_result': scan_result
            })

    return results


