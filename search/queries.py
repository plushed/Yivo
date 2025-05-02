import requests
from requests.auth import HTTPBasicAuth
import time
import logging
import json
import re
import os
import base64
from urllib.parse import urlparse
from urllib.parse import quote
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

def get_api_secret(user, module_name):
    try:
        user_module = UserModule.objects.get(user=user, module__name=module_name)
        return user_module.api_secret
    except UserModule.DoesNotExist:
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

    def _query_section(self, indicator_type, indicator, section):
        api_key = self._get_api_key()
        if not api_key:
            return {"error": "API key not found or not enabled"}

        encoded = quote(indicator, safe="")
        url = f"{self.base_url}/indicators/{indicator_type}/{encoded}/{section}"
        headers = {"X-OTX-API-KEY": api_key}
        response = requests.get(url, headers=headers)
        rate_limit_request()

        try:
            return response.json()
        except Exception:
            return {"error": "Invalid JSON response"}

    def query_ip(self, ip_address):
        sections = ["general", "reputation", "malware"]
        return self._aggregate_sections("IPv4", ip_address, sections)

    def query_domain(self, domain):
        sections = ["general", "malware", "url_list"]
        return self._aggregate_sections("domain", domain, sections)

    def query_url(self, url):
        sections = ["general", "url_list"]
        return self._aggregate_sections("url", url, sections)

    def query_file(self, file_hash):
        sections = ["general", "analysis"]
        return self._aggregate_sections("file", file_hash, sections)

    def _aggregate_sections(self, indicator_type, indicator, sections):
        aggregated = {"indicator": indicator, "type": indicator_type, "sections": {}}
        for section in sections:
            result = self._query_section(indicator_type, indicator, section)
            aggregated["sections"][section] = result
        return aggregated

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
        elif indicator.count(".") == 3:  # Check for IP first
            return "ip"
        elif "." in indicator:
            return "domain"
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
        self.api_secret = get_api_secret(user, module_name)
        self.base_url = "https://api.xforce.ibmcloud.com"

    def _get_auth_headers(self):
        if not self.api_key or not self.api_secret:
            return None
        token = f"{self.api_key}:{self.api_secret}"
        token_bytes = token.encode("utf-8")
        base64_token = base64.b64encode(token_bytes).decode("utf-8")
        headers = {
            "Authorization": f"Basic {base64_token}",
            "Accept": "application/json"
        }
        return headers

    def _make_request(self, endpoint):
        headers = self._get_auth_headers()
        if not headers:
            return {"error": "IBM X-Force API credentials not available."}

        url = f"{self.base_url}/{endpoint}"

        try:
            response = requests.get(url, headers=headers, timeout=15)
            return self._handle_response(response)
        except requests.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}


    def query_file(self, file_hash):
        return self._make_request(f"malware/{file_hash}")

    def query_url(self, url_to_check):
        return self._make_request(f"url/{url_to_check}")

    def query_ip(self, ip_address):
        return self._make_request(f"ipr/{ip_address}")

    def query_domain(self, domain):
        return self._make_request(f"dns/{domain}")

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
        if indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"
        elif indicator.count(".") == 3 and all(part.isdigit() for part in indicator.split(".")):
            return "ip"
        elif len(indicator) in [32, 40, 64]:
            return "file"
        elif "." in indicator:
            return "domain"
        else:
            return "unknown"

    def _handle_response(self, response):
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            return {"error": "Unauthorized."}
        else:
            return {
                "error": "Failed to fetch data from IBM X-Force",
                "status_code": response.status_code,
                "response_text": response.text
            }


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
        self.base_url = "https://api.apivoid.com/v2"
        self.user = user
        self.module_name = "APIVoid"

    def _get_api_key(self):
        return get_api_key(self.user, self.module_name)

    def query_ip(self, ip_address):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/ip-reputation"
            headers = {"X-API-Key": api_key}
            payload = {"ip": ip_address}
            response = requests.post(url, json=payload, headers=headers)
            return response.json()
        return {"error": "API key not found or not enabled"}

    def query_url(self, url):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/url-reputation"
            headers = {"X-API-Key": api_key}
            payload = {"url": url}
            response = requests.post(url, json=payload, headers=headers)
            return response.json()
        return {"error": "API key not found or not enabled"}

    def query_domain(self, domain):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/domain-reputation"
            headers = {"X-API-Key": api_key}
            payload = {"domain": domain}
            response = requests.post(url, json=payload, headers=headers)
            return response.json()
        return {"error": "API key not found or not enabled"}

    def query_file(self, file_hash):
        api_key = self._get_api_key()
        if api_key:
            url = f"{self.base_url}/file-reputation"
            headers = {"X-API-Key": api_key}
            payload = {"file": file_hash}
            response = requests.post(url, json=payload, headers=headers)
            return response.json()
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
                response_json = response.json()

                if response_json.get("query_status") == "no_result":
                    return {"error": "No results found for the given indicator"}

                # Correct check: look for "data", not "indicator"
                if isinstance(response_json, dict) and "data" in response_json:
                    data = response_json.get("data", [])
                    if isinstance(data, list) and data:  # data is a non-empty list
                        return response_json
                    else:
                        return {"error": "No data returned for this indicator"}
                else:
                    return {"error": "Unexpected response format: missing 'data' field"}
            except ValueError:
                return {"error": "Failed to parse JSON, invalid response format"}
        else:
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
    def __init__(self, user=None, module_name="URLHausOffline"):
        self.module_name = module_name
        self.feed_path = FEED_PATHS.get("urlhaus", "search/feeds/urlhaus_full.json")

    def query(self, indicator: str) -> list:
        if not os.path.exists(self.feed_path):
            return [{"error": "URLHaus feed file not found"}]

        matches = []

        # Check if the indicator is a URL or a domain
        is_url = indicator.startswith("http://") or indicator.startswith("https://")

        try:
            with open(self.feed_path, "r", encoding="utf-8") as f:
                data = json.load(f)

                for entry_id, entries in data.items():
                    for item in entries:
                        item_url = item.get("url", "")
                        parsed = urlparse(item_url)
                        domain = parsed.netloc

                        if is_url and indicator == item_url:
                            matches.append(item)
                        elif not is_url and indicator == domain:
                            matches.append(item)

        except Exception as e:
            return [{"error": f"Error reading URLHaus feed: {str(e)}"}]

        return matches


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
            print("❌ Missing API key")
            return {"error": "API key not available"}

        url = f"{self.base_url}{ip_address}"
        headers = {
            "Authorization": f"Bearer {self.api_key}"
        }

        try:
            response = requests.get(url, headers=headers)
            print(f"➡️ Request URL: {url}")
            print(f"➡️ Headers: {headers}")
            print(f"⬅️ Status Code: {response.status_code}")
            print(f"⬅️ Response Body: {response.text}")

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Failed to fetch data from GreyNoise: {response.status_code}"}

        except requests.RequestException as e:
            print(f"❌ Request Exception: {e}")
            return {"error": f"Exception occurred: {str(e)}"}

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
    def __init__(self, user=None, module_name="CINSscore"):
        self.module_name = module_name
        self.feed_path = FEED_PATHS.get("cins", "../../feeds/ci-badguys.txt")  # Default fallback path

    def query_ip(self, ip_address: str) -> list:
        matches = []

        if not os.path.exists(self.feed_path):
            return [{"error": "CINS feed file not found"}]

        try:
            with open(self.feed_path, "r", encoding="utf-8") as f:
                for line in f:
                    line_ip = line.strip().split()[0]  # In case the line includes IP + metadata
                    if ip_address == line_ip:
                        matches.append(line.strip())
        except Exception as e:
            return [{"error": f"Error reading CINS feed: {str(e)}"}]

        if not matches:
            return []

        return matches

    def query(self, indicator: str) -> list:
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "ip":
            return self.query_ip(indicator)
        else:
            return [{"error": "CINSscore only supports IP address queries"}]

    def determine_indicator_type(self, indicator):
        if indicator.count(".") == 3:  # Basic IPv4 check
            return "ip"
        return "unknown"


class IPWhoisQuery:
    def __init__(self, user=None, module_name="IPWhois"):
        self.base_url = "https://ipwho.is/"
        # No API key required

    def query_ip(self, ip_address):
        if not self.is_valid_ip(ip_address):
            return {"error": "Invalid IP address format"}

        url = f"{self.base_url}{ip_address}"
        try:
            response = requests.get(url)
            print(f"➡️ Request URL: {url}")
            print(f"⬅️ Status Code: {response.status_code}")
            print(f"⬅️ Response Body: {response.text}")

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    return data
                else:
                    return {"error": data.get("message", "Unknown error")}
            else:
                return {"error": f"Failed to fetch data from ipwho.is: {response.status_code}"}

        except requests.RequestException as e:
            print(f"❌ Request Exception: {e}")
            return {"error": f"Exception occurred: {str(e)}"}

    def query(self, indicator):
        indicator_type = self.determine_indicator_type(indicator)
        if indicator_type == "ip":
            return self.query_ip(indicator)
        else:
            return {"error": "ipwho.is only supports IP queries"}

    def determine_indicator_type(self, indicator):
        return "ip" if self.is_valid_ip(indicator) else "unknown"

    def is_valid_ip(self, ip):
        pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        return re.match(pattern, ip) is not None