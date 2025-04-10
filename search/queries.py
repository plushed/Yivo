import base64
import requests

class VirusTotalQuery:
    def __init__(self):
        self.api_key = "your_virustotal_api_key"
        self.base_url = "https://www.virustotal.com/api/v3"

    def query_file(self, file_hash):
        url = f"{self.base_url}/files/{file_hash}"
        headers = {"x-apikey": self.api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from VirusTotal"}

    def query_url(self, url):
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        url = f"{self.base_url}/urls/{encoded_url}"
        headers = {"x-apikey": self.api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from VirusTotal"}

    def query_ip(self, ip_address):
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        headers = {"x-apikey": self.api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from VirusTotal"}

    def query_domain(self, domain):
        url = f"{self.base_url}/domains/{domain}"
        headers = {"x-apikey": self.api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from VirusTotal"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "file":
            return self.query_file(indicator)
        elif indicator_type == "url":
            return self.query_url(indicator)
        elif indicator_type == "ip":
            return self.query_ip(indicator)
        elif indicator_type == "domain":
            return self.query_domain(indicator)
        else:
            return {"error": "Unsupported indicator type"}

    def determine_indicator_type(self, indicator):
        # You can add more sophisticated checks for different indicator types.
        if len(indicator) == 32 or len(indicator) == 40 or len(indicator) == 64:
            return "file"
        elif indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"
        elif "." in indicator:
            return "domain"
        elif indicator.count(".") == 3:  # Basic check for an IP address
            return "ip"
        else:
            return "unknown"

class AlienVaultQuery:
    def __init__(self):
        self.api_key = "your_alienvault_api_key"
        self.base_url = "https://otx.alienvault.com/api/v1"

    def query_file(self, file_hash):
        url = f"{self.base_url}/indicators/file/{file_hash}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from AlienVault"}

    def query_url(self, url):
        url = f"{self.base_url}/indicators/url/{url}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from AlienVault"}

    def query_ip(self, ip_address):
        url = f"{self.base_url}/indicators/IPv4/{ip_address}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from AlienVault"}

    def query_domain(self, domain):
        url = f"{self.base_url}/indicators/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from AlienVault"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "file":
            return self.query_file(indicator)
        elif indicator_type == "url":
            return self.query_url(indicator)
        elif indicator_type == "ip":
            return self.query_ip(indicator)
        elif indicator_type == "domain":
            return self.query_domain(indicator)
        else:
            return {"error": "Unsupported indicator type"}

    def determine_indicator_type(self, indicator):
        # You can add more sophisticated checks for different indicator types.
        if len(indicator) == 32 or len(indicator) == 40 or len(indicator) == 64:
            return "file"
        elif indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"
        elif "." in indicator:
            return "domain"
        elif indicator.count(".") == 3:  # Basic check for an IP address
            return "ip"
        else:
            return "unknown"

class IBMXForceQuery:
    def __init__(self):
        self.api_key = "your_ibm_xforce_api_key"
        self.base_url = "https://api.xforce.ibmcloud.com"

    def query_file(self, file_hash):
        url = f"{self.base_url}/filereputation/{file_hash}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from IBM X-Force"}

    def query_url(self, url):
        url = f"{self.base_url}/url/{url}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from IBM X-Force"}

    def query_ip(self, ip_address):
        url = f"{self.base_url}/ipr/{ip_address}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from IBM X-Force"}

    def query_domain(self, domain):
        url = f"{self.base_url}/dns/{domain}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from IBM X-Force"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "file":
            return self.query_file(indicator)
        elif indicator_type == "url":
            return self.query_url(indicator)
        elif indicator_type == "ip":
            return self.query_ip(indicator)
        elif indicator_type == "domain":
            return self.query_domain(indicator)
        else:
            return {"error": "Unsupported indicator type"}

    def determine_indicator_type(self, indicator):
        # You can add more sophisticated checks for different indicator types.
        if len(indicator) == 32 or len(indicator) == 40 or len(indicator) == 64:
            return "file"
        elif indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"
        elif "." in indicator:
            return "domain"
        elif indicator.count(".") == 3:  # Basic check for an IP address
            return "ip"
        else:
            return "unknown"

class CiscoTalosQuery:
    def __init__(self):
        self.api_key = "your_cisco_talos_api_key"
        self.base_url = "https://api.talosintelligence.com"

    def query_ip(self, ip_address):
        url = f"{self.base_url}/ip_reputation/{ip_address}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from Cisco Talos"}

    def query_domain(self, domain):
        url = f"{self.base_url}/domain_reputation/{domain}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from Cisco Talos"}

    def query_url(self, url):
        url = f"{self.base_url}/url_reputation/{url}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from Cisco Talos"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "ip":
            return self.query_ip(indicator)
        elif indicator_type == "domain":
            return self.query_domain(indicator)
        elif indicator_type == "url":
            return self.query_url(indicator)
        else:
            return {"error": "Unsupported indicator type"}

    def determine_indicator_type(self, indicator):
        if indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"
        elif "." in indicator:
            return "domain"
        elif indicator.count(".") == 3:  # Basic check for an IP address
            return "ip"
        else:
            return "unknown"

class ShodanQuery:
    def __init__(self):
        self.api_key = "your_shodan_api_key"
        self.base_url = "https://api.shodan.io"

    def query_ip(self, ip_address):
        url = f"{self.base_url}/shodan/host/{ip_address}?key={self.api_key}"
        response = requests.get(url)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from Shodan"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "ip":
            return self.query_ip(indicator)
        else:
            return {"error": "Shodan only supports IP queries"}

    def determine_indicator_type(self, indicator):
        if indicator.count(".") == 3:  # Basic check for an IP address
            return "ip"
        else:
            return "unknown"

class CensysQuery:
    def __init__(self):
        self.api_id = "your_censys_api_id"
        self.api_secret = "your_censys_api_secret"
        self.base_url = "https://censys.io/api/v1"

    def query_ip(self, ip_address):
        url = f"{self.base_url}/view/ipv4/{ip_address}"
        auth = (self.api_id, self.api_secret)
        response = requests.get(url, auth=auth)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from Censys"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "ip":
            return self.query_ip(indicator)
        else:
            return {"error": "Censys only supports IP queries"}

    def determine_indicator_type(self, indicator):
        if indicator.count(".") == 3:  # Basic check for an IP address
            return "ip"
        else:
            return "unknown"

class AbuseIPDBQuery:
    def __init__(self):
        self.api_key = "your_abuseipdb_api_key"
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    def query_ip(self, ip_address):
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90  # Optional: Limit to reports in the last 90 days
        }
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

        response = requests.get(self.base_url, params=params, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from AbuseIPDB"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "ip":
            return self.query_ip(indicator)
        else:
            return {"error": "AbuseIPDB only supports IP queries"}

    def determine_indicator_type(self, indicator):
        if indicator.count(".") == 3:  # Basic check for an IP address
            return "ip"
        else:
            return "unknown"

class GreyNoiseQuery:
    def __init__(self):
        self.api_key = "your_greynoise_api_key"
        self.base_url = "https://api.greynoise.io/v3/community/"

    def query_ip(self, ip_address):
        url = f"{self.base_url}{ip_address}"
        headers = {
            "Authorization": f"Bearer {self.api_key}"
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from GreyNoise"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "ip":
            return self.query_ip(indicator)
        else:
            return {"error": "GreyNoise only supports IP queries"}

    def determine_indicator_type(self, indicator):
        if indicator.count(".") == 3:  # Basic check for an IP address
            return "ip"
        else:
            return "unknown"

class URLScanQuery:
    def __init__(self):
        self.api_key = "your_urlscan_api_key"
        self.base_url = "https://urlscan.io/api/v1/result/"

    def query_url(self, uuid):
        url = f"{self.base_url}{uuid}/"
        headers = {
            "API-Key": self.api_key
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from URLScan"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "url":
            return self.query_url(indicator)
        else:
            return {"error": "URLScan only supports URL queries"}

    def determine_indicator_type(self, indicator):
        if "://" in indicator:  # Basic check for a URL
            return "url"
        else:
            return "unknown"

class PhishLabsQuery:
    def __init__(self):
        self.api_key = "your_phishlabs_api_key"
        self.base_url = "https://api.phishlabs.com/api/v1/urls/"

    def query_url(self, url_hash):
        url = f"{self.base_url}{url_hash}"
        headers = {
            "Authorization": f"Bearer {self.api_key}"
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from PhishLabs"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "url":
            url_hash = self.get_url_hash(indicator)
            return self.query_url(url_hash)
        else:
            return {"error": "PhishLabs only supports URL queries"}

    def determine_indicator_type(self, indicator):
        if "://" in indicator:  # Basic check for a URL
            return "url"
        else:
            return "unknown"

    def get_url_hash(self, url):
        # This method would hash the URL (for example using SHA256) to query PhishLabs
        import hashlib
        return hashlib.sha256(url.encode('utf-8')).hexdigest()