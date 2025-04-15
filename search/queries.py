import requests
import time
import logging
import json
import re
from django.core.cache import cache
from django.db.models import Q
from .models import UserModule, Module
from requests.exceptions import RequestException

# Set up logger
logger = logging.getLogger(__name__)

# Helper function to retrieve API key for a given user and module
def get_api_key(user, module_name):
    try:
        # Get the UserModule instance for the provided user and module
        user_module = UserModule.objects.get(user=user, module__name=module_name)
        if user_module.enabled and user_module.api_key:
            return user_module.api_key
        else:
            logger.warning(f"API key not enabled or found for {module_name} and user {user.username}")
            return None
    except UserModule.DoesNotExist:
        logger.warning(f"No UserModule entry found for user {user.username} and module {module_name}")
        return None

# Helper function to handle rate limiting (sleep time between requests)
def rate_limit_request():
    # Simple rate limiting: sleep for 1 second before making the next request
    time.sleep(1)

# Helper function to handle API call and caching
def api_call_with_cache(url, params, cache_key):
    # Check if the result is cached
    cached_result = cache.get(cache_key)
    if cached_result:
        logger.info("Returning cached result for " + cache_key)
        return cached_result

    try:
        # Make the API request
        response = requests.get(url, params=params)
        response.raise_for_status()
        
        # Cache the result for future use (5 minutes expiration)
        cache.set(cache_key, response.json(), timeout=300)  # Cache for 5 minutes
        return response.json()
    except RequestException as e:
        logger.error(f"API request failed: {e}")
        return None

class VirusTotalQuery:
    def __init__(self, user):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.user = user
        self.module_name = "VirusTotal"

    def _get_api_key(self):
        return get_api_key(self.user, self.module_name)

    def query_file(self, file_hash):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/files/{file_hash}"  # Directly use the file hash, no encoding required
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers)
            rate_limit_request()
            return self._handle_response(response)
        return {"error": "API key not found or not enabled"}

    def query_url(self, url):
        api_key = self._get_api_key()
        if api_key:
            # Base64 encode URL (only URLs need encoding)
            encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            url = f"{self.base_url}/urls/{encoded_url}"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers)
            rate_limit_request()
            return self._handle_response(response)
        return {"error": "API key not found or not enabled"}

    def query_ip(self, ip_address):
        api_key = self._get_api_key()
        if api_key:
            # IP addresses are used as-is without base64 encoding
            url = f"{self.base_url}/ip_addresses/{ip_address}"  # No encoding needed for IP addresses
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers)
            rate_limit_request()
            return self._handle_response(response)
        return {"error": "API key not found or not enabled"}

    def query_domain(self, domain):
        api_key = self._get_api_key()
        if api_key:
            # Domains are used as-is, no base64 encoding required for domains
            url = f"{self.base_url}/domains/{domain}"  # No encoding needed for domains
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers)
            rate_limit_request()
            return self._handle_response(response)
        return {"error": "API key not found or not enabled"}

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
        # Enhanced check to better detect indicator types
        if len(indicator) == 32 or len(indicator) == 40 or len(indicator) == 64:
            return "file"  # File hash
        elif indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"  # URL
        elif "." in indicator:
            # Check if it's a valid domain or IP address
            if indicator.count(".") == 3 and all(i.isdigit() for i in indicator.split(".")):
                return "ip"  # IP address
            return "domain"  # Domain
        else:
            return "unknown"

    def _handle_response(self, response):
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Failed to fetch data (status code: {response.status_code})"}

class AlienVaultQuery:
    def __init__(self, user):
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.user = user
        self.module_name = "AlienVault"

    def _get_api_key(self):
        return get_api_key(self.user, self.module_name)

    def query_file(self, file_hash):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/indicators/file/{file_hash}/general"
            headers = {"X-OTX-API-KEY": api_key}
            response = requests.get(url, headers=headers)
            rate_limit_request()
            return self._handle_response(response)
        return {"error": "API key not found or not enabled"}

    def query_url(self, url):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/indicators/url/{url}/general"
            headers = {"X-OTX-API-KEY": api_key}
            response = requests.get(url, headers=headers)
            rate_limit_request()
            return self._handle_response(response)
        return {"error": "API key not found or not enabled"}

    def query_ip(self, ip_address):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/indicators/IPv4/{ip_address}/general"
            headers = {"X-OTX-API-KEY": api_key}
            response = requests.get(url, headers=headers)
            rate_limit_request()
            return self._handle_response(response)
        return {"error": "API key not found or not enabled"}

    def query_domain(self, domain):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/indicators/domain/{domain}/general"
            headers = {"X-OTX-API-KEY": api_key}
            response = requests.get(url, headers=headers)
            rate_limit_request()
            return self._handle_response(response)
        return {"error": "API key not found or not enabled"}

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

    def _handle_response(self, response):
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Failed to fetch data (status code: {response.status_code})"}

class IBMXForceQuery:
    def __init__(self, user, module_name="IBM X-Force"):
        self.api_key = get_api_key(user, module_name)
        self.base_url = "https://api.xforce.ibmcloud.com"

    def query_file(self, file_hash):
        if not self.api_key:
            return {"error": "API key not available"}
        
        url = f"{self.base_url}/filereputation/{file_hash}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from IBM X-Force"}

    def query_url(self, url):
        if not self.api_key:
            return {"error": "API key not available"}
        
        url = f"{self.base_url}/url/{url}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from IBM X-Force"}

    def query_ip(self, ip_address):
        if not self.api_key:
            return {"error": "API key not available"}
        
        url = f"{self.base_url}/ipr/{ip_address}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from IBM X-Force"}

    def query_domain(self, domain):
        if not self.api_key:
            return {"error": "API key not available"}
        
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
        if len(indicator) == 32 or len(indicator) == 40 or len(indicator) == 64:
            return "file"
        elif indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"
        elif "." in indicator:
            return "domain"
        elif indicator.count(".") == 3:
            return "ip"
        else:
            return "unknown"

class CiscoTalosQuery:
    def __init__(self, user, module_name="Cisco Talos"):
        self.api_key = get_api_key(user, module_name)
        self.base_url = "https://api.talosintelligence.com"

    def query_ip(self, ip_address):
        if not self.api_key:
            return {"error": "API key not available"}
        
        url = f"{self.base_url}/ip_reputation/{ip_address}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from Cisco Talos"}

    def query_domain(self, domain):
        if not self.api_key:
            return {"error": "API key not available"}
        
        url = f"{self.base_url}/domain_reputation/{domain}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch data from Cisco Talos"}

    def query_url(self, url):
        if not self.api_key:
            return {"error": "API key not available"}
        
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
        elif indicator.count(".") == 3:
            return "ip"
        else:
            return "unknown"

class ShodanQuery:
    def __init__(self, user, module_name="Shodan"):
        self.api_key = get_api_key(user, module_name)
        self.base_url = "https://api.shodan.io"

    def query_ip(self, ip_address):
        if not self.api_key:
            return {"error": "API key not available"}
        
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
    def __init__(self, user, module_name="Censys"):
        self.api_id = get_api_key(user, f"{module_name}_ID")
        self.api_secret = get_api_key(user, f"{module_name}_SECRET")
        self.base_url = "https://censys.io/api/v1"

    def query_ip(self, ip_address):
        if not self.api_id or not self.api_secret:
            return {"error": "API keys not available"}
        
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
    def __init__(self, user, module_name="AbuseIPDB"):
        self.api_key = get_api_key(user, module_name)
        self.base_url = "https://api.abuseipdb.com/api/v2/check"
    
    def query_ip(self, ip_address):
        if not self.api_key:
            return {"error": "API key not available"}
        
        # Ensure IP address is a valid IPv4 address
        if not self.is_valid_ip(ip_address):
            return {"error": "Invalid IP address format"}
        
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90  # Optional: Limit to reports in the last 90 days
        }
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

        response = requests.get(self.base_url, params=params, headers=headers)
        
        # Print the raw response to understand the issue better
        print("Raw Response:", response.text)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Failed to fetch data from AbuseIPDB: {response.status_code}"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "ip":
            return self.query_ip(indicator)
        else:
            return {"error": "AbuseIPDB only supports IP queries"}

    def determine_indicator_type(self, indicator):
        if self.is_valid_ip(indicator):  # Use more robust IP check
            return "ip"
        else:
            return "unknown"

    def is_valid_ip(self, ip):
        # Simple regex to check if it's a valid IPv4 address
        pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        return re.match(pattern, ip) is not None

class GreyNoiseQuery:
    def __init__(self, user, module_name="GreyNoise"):
        self.api_key = get_api_key(user, module_name)
        self.base_url = "https://api.greynoise.io/v3/community/"

    def query_ip(self, ip_address):
        if not self.api_key:
            return {"error": "API key not available"}
        
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
    def __init__(self, user, module_name="URLScan"):
        self.api_key = get_api_key(user, module_name)
        self.base_url = "https://urlscan.io/api/v1/result/"

    def query_url(self, uuid):
        if not self.api_key:
            return {"error": "API key not available"}
        
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
    def __init__(self, user, module_name="PhishLabs"):
        self.api_key = get_api_key(user, module_name)
        self.base_url = "https://api.phishlabs.com/api/v1/urls/"

    def query_url(self, url_hash):
        if not self.api_key:
            return {"error": "API key not available"}
        
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
