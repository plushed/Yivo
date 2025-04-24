import requests
import time
import logging
import json
import re
from django.core.cache import cache
from django.db.models import Q
from .models import UserModule, Module
from requests.exceptions import RequestException
from search.constants   import FEED_PATHS

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

class APIVoidQuery:
    def __init__(self, user):
        self.base_url = "https://endpoint.apivoid.com"
        self.user = user
        self.module_name = "APIVoid"

    def _get_api_key(self):
        return get_api_key(self.user, self.module_name)

    def query_ip(self, ip_address):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/iprep/{ip_address}"
            params = {"key": api_key}
            return api_call_with_cache(url, params, f"apivoid_ip_{ip_address}")
        return {"error": "API key not found or not enabled"}

    def query_url(self, url):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/urlrep/{url}"
            params = {"key": api_key}
            return api_call_with_cache(url, params, f"apivoid_url_{url}")
        return {"error": "API key not found or not enabled"}

    def query_domain(self, domain):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/domainrep/{domain}"
            params = {"key": api_key}
            return api_call_with_cache(url, params, f"apivoid_domain_{domain}")
        return {"error": "API key not found or not enabled"}

    def query_file(self, file_hash):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/filerep/{file_hash}"
            params = {"key": api_key}
            return api_call_with_cache(url, params, f"apivoid_file_{file_hash}")
        return {"error": "API key not found or not enabled"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "ip":
            return self.query_ip(indicator)
        elif indicator_type == "url":
            return self.query_url(indicator)
        elif indicator_type == "domain":
            return self.query_domain(indicator)
        elif indicator_type == "file":
            return self.query_file(indicator)
        else:
            return {"error": "Unsupported indicator type"}

    def determine_indicator_type(self, indicator):
        if len(indicator) == 32 or len(indicator) == 40 or len(indicator) == 64:
            return "file"  # File hash
        elif indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"  # URL
        elif "." in indicator:
            return "domain"  # Domain
        elif indicator.count(".") == 3:
            return "ip"  # IP address
        else:
            return "unknown"

class ThreatFoxQuery:
    def __init__(self, user):
        self.base_url = "https://threatfox-api.abuse.ch/api/v1/"  # <- trailing slash is required
        self.user = user
        self.module_name = "ThreatFox"

    def _get_api_key(self):
        return get_api_key(self.user, self.module_name)

    def query(self, indicator):
        api_key = self._get_api_key()
        if not api_key:
            return {"error": "API key not found or not enabled"}

        payload = {
            "query": "search_ioc",
            "search_term": indicator
        }

        headers = {
            "API-KEY": api_key  # MUST be "API-KEY" (not "API-Key")
        }

        try:
            response = requests.post(self.base_url, json=payload, headers=headers)
            rate_limit_request()
            return self._handle_response(response)
        except requests.RequestException as e:
            return {"error": f"Request error: {str(e)}"}

    def _handle_response(self, response):
        if response.status_code == 200:
            try:
                # Try to parse the JSON response
                response_json = response.json()

                # Debugging: Log the full response structure to inspect it
                print("Full Response JSON:", response_json)

                # Handle the case where no results are found
                if response_json.get("query_status") == "no_result":
                    return {"error": "No results found for the given indicator"}

                # If response contains 'indicator', return it, otherwise log error
                if isinstance(response_json, dict):
                    if "indicator" in response_json:
                        return response_json
                    else:
                        return {"error": "Expected 'indicator' field not found in response"}
                else:
                    return {"error": "Unexpected response format: JSON was not a dictionary"}
            except ValueError:
                return {"error": "Failed to parse JSON, invalid response format"}
        else:
            # Log status code and response text for debugging
            return {
                "error": f"Failed to fetch data (status code: {response.status_code})",
                "response": response.text
            }

class MalwareBazaarQuery:
    def __init__(self, user):
        self.base_url = "https://mb-api.abuse.ch/api/v1/"
        self.user = user
        self.module_name = "MalwareBazaar"

    def _get_api_key(self):
        return get_api_key(self.user, self.module_name)

    def query(self, indicator):
        api_key = self._get_api_key()
        if not api_key:
            return {"error": "API key not found or not enabled"}

        payload = {
            "query": "get_info",
            "hash": indicator
        }

        headers = {
            "API-KEY": api_key
        }

        try:
            response = requests.post(self.base_url, json=payload, headers=headers)
            rate_limit_request()
            return self._handle_response(response)
        except requests.RequestException as e:
            return {"error": f"Request error: {str(e)}"}

    def _handle_response(self, response):
        if response.status_code == 200:
            try:
                response_json = response.json()
                print("Full Response JSON:", response_json)

                if response_json.get("query_status") == "no_results":
                    return {"error": "No results found for the given hash"}

                if "data" in response_json:
                    return response_json["data"]
                else:
                    return {"error": "Expected 'data' field not found in response"}
            except ValueError:
                return {"error": "Failed to parse JSON, invalid response format"}
        else:
            return {
                "error": f"Failed to fetch data (status code: {response.status_code})",
                "response": response.text
            }

class URLHausQuery:
    def __init__(self, user):
        self.base_url = "https://urlhaus-api.abuse.ch/v1/"
        self.user = user
        self.module_name = "URLHaus"

    def _get_api_key(self):
        return get_api_key(self.user, self.module_name)

    def query(self, indicator):
        api_key = self._get_api_key()
        if not api_key:
            return {"error": "API key not found or not enabled"}

        payload = {
            "url": indicator
        }

        headers = {
            "API-KEY": api_key
        }

        try:
            response = requests.post(self.base_url + "url/", json=payload, headers=headers)
            rate_limit_request()
            return self._handle_response(response)
        except requests.RequestException as e:
            return {"error": f"Request error: {str(e)}"}

    def _handle_response(self, response):
        if response.status_code == 200:
            try:
                response_json = response.json()
                print("Full Response JSON:", response_json)

                if response_json.get("query_status") == "no_results":
                    return {"error": "No results found for the given URL"}

                if "url" in response_json:
                    return response_json
                else:
                    return {"error": "Expected 'url' field not found in response"}
            except ValueError:
                return {"error": "Failed to parse JSON, invalid response format"}
        else:
            return {
                "error": f"Failed to fetch data (status code: {response.status_code})",
                "response": response.text
            }

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

class OnionooQuery:
    def __init__(self, user, module_name="Onionoo"):
        # No API key needed for Onionoo, but still storing module_name for consistency
        self.base_url = "https://onionoo.torproject.org/details"

    def query_ip(self, ip_address):
        params = {
            "search": ip_address
        }

        try:
            response = requests.get(self.base_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return self._parse_response(data, ip_address)
            else:
                return {"error": f"Failed to fetch data from Onionoo: {response.status_code}"}
        except requests.RequestException as e:
            return {"error": f"Request error: {str(e)}"}

    def _parse_response(self, data, ip_address):
        relays = data.get("relays", [])
        if not relays:
            return {
                "ip": ip_address,
                "tor_exit_node": False,
                "message": "IP address not found in Onionoo exit node data."
            }

        # You could expand this to include more metadata
        return {
            "ip": ip_address,
            "tor_exit_node": True,
            "matches": relays  # Includes full matching relay details
        }

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "ip":
            return self.query_ip(indicator)
        else:
            return {"error": "Onionoo only supports IP address queries"}

    def determine_indicator_type(self, indicator):
        if indicator.count(".") == 3:
            return "ip"
        return "unknown"

class PhishTankQuery:
    def __init__(self, user, module_name="PhishTank"):
        # Requires API key from user for authenticating requests
        self.base_url = "https://check.phishtank.com/checkphoenix/"
        self.api_key = user.api_key  # Assuming API key is stored in the user model

    def query_url(self, url):
        params = {
            "url": url,
            "format": "json",
            "api_key": self.api_key
        }

        try:
            response = requests.get(self.base_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return self._parse_response(data, url)
            else:
                return {"error": f"Failed to fetch data from PhishTank: {response.status_code}"}
        except requests.RequestException as e:
            return {"error": f"Request error: {str(e)}"}

    def _parse_response(self, data, url):
        if "error" in data:
            return {"error": data["error"]}

        # PhishTank returns a "phish_id" and verification status
        phish_status = data.get("phish_status", "unknown")
        if phish_status == "phishing":
            return {
                "url": url,
                "is_phishing": True,
                "phish_id": data.get("phish_id", ""),
                "message": "This URL is confirmed to be phishing."
            }
        else:
            return {
                "url": url,
                "is_phishing": False,
                "message": "This URL is not recognized as phishing."
            }

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "url":
            return self.query_url(indicator)
        else:
            return {"error": "PhishTank only supports URL queries"}

    def determine_indicator_type(self, indicator):
        # Assuming basic validation for URL format
        if isinstance(indicator, str) and indicator.startswith("http"):
            return "url"
        return "unknown"

class OpenPhishQuery:
    def search(self, indicator: str) -> list:
        matches = []
        try:
            with open(FEED_PATHS["openphish"], "r", encoding="utf-8") as f:
                for line in f:
                    if indicator in line:
                        matches.append(line.strip())
        except Exception as e:
            return [{"error": f"Error reading OpenPhish feed: {str(e)}"}]
        
        return [standardize_openphish_score(match, indicator) for match in matches]

class CINSscoreQuery:
    def search(self, indicator: str) -> list:
        matches = []
        try:
            with open(FEED_PATHS["cins"], "r", encoding="utf-8") as f:
                for line in f:
                    if indicator in line:
                        matches.append(line.strip())
        except Exception as e:
            return [{"error": f"Error reading CINS feed: {str(e)}"}]
        
        return [standardize_cins_score(match, indicator) for match in matches]