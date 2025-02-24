import config
import requests


def whois_analysis(domain_name):
    try:
        end_point = f"{config.MySecret.IP2LOCATION_API_ENDPOINT}?key={config.MySecret.IP2LOCATION_API_KEY}&domain={domain_name}"
        response = requests.get(end_point)

        if response.status_code == 200:
            data = response.json()
            return data
        else:
            return {"error": f"Request failed with status code {response.status_code}"}

    except requests.exceptions.RequestException as e:
        return {"error": f"An error occurred: {str(e)}"}


