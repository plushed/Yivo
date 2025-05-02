# search/module_handlers.py
import logging
from .utils import calculate_overall_risk_score
from .models import UserModule
import re

# Initialize the logger
logger = logging.getLogger(__name__)

def standardize_abuseipdb(result, indicator=None):
    if not isinstance(result, dict) or "errors" in result:
        return {
            "module": "abuseipdb",
            "indicator": indicator,
            "risk_score": "N/A",
            "summary": {"error": result.get("errors") if isinstance(result, dict) else "Invalid format"},
            "raw": result
        }

    data = result.get("data", {})
    ip_address = data.get("ipAddress", indicator)

    if not data or ip_address is None:
        return {
            "module": "abuseipdb",
            "indicator": indicator,
            "risk_score": 0,  # IP not found, treat as benign
            "summary": {"note": "No data found for IP"},
            "raw": result
        }

    risk_score = calculate_abuseipdb_score(data)

    return {
        "module": "abuseipdb",
        "indicator": ip_address,
        "risk_score": risk_score,
        "summary": {
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "totalReports": data.get("totalReports"),
            "isTor": data.get("isTor"),
            "countryCode": data.get("countryCode"),
            "domain": data.get("domain"),
        },
        "raw": result,
    }



def calculate_abuseipdb_score(data):
    # Get the basic confidence score
    confidence_score = data.get("abuseConfidenceScore", 0)
    
    # Get additional factors that can influence the risk score
    is_tor = data.get("isTor", False)
    country_code = data.get("countryCode", "")
    
    # List of countries considered high-risk (e.g., OFAC list, or other high-risk nations)
    risky_countries = {"CN", "IR", "KP", "SY", "CU", "SD", "VE", "UA"}  # Example: China, Iran, North Korea, Syria, Cuba, Sudan, Venezuela, Ukraine
    
    # Start with the confidence score
    risk_score = confidence_score
    
    # If confidence score is 0, use other factors to calculate the score
    if confidence_score == 0:
        if is_tor:
            # Tor nodes are considered high risk
            risk_score = max(risk_score, 60)  # Minimum risk score if Tor node is detected
        
        if country_code in risky_countries:  # Check if the country is in the high-risk list
            # Increase risk for certain high-risk countries
            risk_score = max(risk_score, 70)  # Minimum score for risky countries
    
    # Ensure the score is between 0 and 100
    return min(risk_score, 100)

def standardize_virustotal(result, original_indicator=None):
    if not isinstance(result, dict) or "error" in result:
        return {
            "module": "virustotal",
            "indicator": original_indicator,
            "risk_score": "N/A",
            "summary": {"error": result.get("error") if isinstance(result, dict) else "Invalid format"},
            "raw": result
        }

    data = result.get("data", {})
    attributes = data.get("attributes", {})

    last_analysis_stats = attributes.get("last_analysis_stats", {})
    if not last_analysis_stats:
        return {
            "module": "virustotal",
            "indicator": original_indicator or data.get("id", "unknown"),
            "risk_score": 0,  # No detections, likely benign or not found
            "summary": {},
            "raw": result,
        }

    malicious = last_analysis_stats.get("malicious", 0)
    suspicious = last_analysis_stats.get("suspicious", 0)
    undetected = last_analysis_stats.get("undetected", 0)
    harmless = last_analysis_stats.get("harmless", 0)
    reputation = attributes.get("reputation", 0)

    total_votes = attributes.get("total_votes", {})
    total_malicious = total_votes.get("malicious", 0)
    total_harmless = total_votes.get("harmless", 0)

    return {
        "module": "virustotal",
        "indicator": original_indicator or data.get("id", "unknown"),
        "risk_score": calculate_virustotal_score(last_analysis_stats),
        "summary": {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "harmless": harmless,
            "reputation": reputation,
            "total_malicious_votes": total_malicious,
            "total_harmless_votes": total_harmless,
        },
        "raw": result,
    }


def calculate_virustotal_score(last_analysis_stats):
    malicious = last_analysis_stats.get("malicious", 0)
    suspicious = last_analysis_stats.get("suspicious", 0)
    harmless = last_analysis_stats.get("harmless", 0)

    if malicious >= 10:
        return 100
    elif malicious >= 5:
        return 90 + suspicious * 2
    elif malicious > 0:
        return 70 + suspicious * 2
    elif suspicious >= 5:
        return 50
    elif suspicious > 0:
        return 30
    else:
        return 0

def standardize_alienvault(result, indicator=None):
    if not isinstance(result, dict) or "error" in result:
        return {
            "module": "alienvault",
            "indicator": indicator,
            "risk_score": "N/A",
            "summary": {"error": result.get("error") if isinstance(result, dict) else "Invalid format"},
            "raw": result
        }

    sections = result.get("sections", {})

    # Extract from each section if present
    general = sections.get("general", {})
    malware_section = sections.get("malware", {})
    reputation_section = sections.get("reputation", {})
    
    # Pulse count is only available in 'general'
    pulse_info = general.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)

    # Malware could be a list or a dict with a 'data' key depending on endpoint
    malware_data = malware_section.get("data", malware_section) if malware_section else []
    malware_count = len(malware_data) if isinstance(malware_data, list) else 0

    # Reputation is a single int field in reputation section
    reputation_score = reputation_section.get("reputation", 0)

    # Compute risk score
    risk_score = calculate_alienvault_score({
        "pulse_info": pulse_info,
        "malware": malware_data,
        "reputation": reputation_score
    })

    return {
        "module": "alienvault",
        "indicator": result.get("indicator", indicator),
        "risk_score": risk_score,
        "summary": {
            "pulse_count": pulse_count,
            "malware_count": malware_count,
            "reputation": reputation_score
        },
        "raw": result
    }

def calculate_alienvault_score(data):
    pulse_count = data.get("pulse_info", {}).get("count", 0)
    malware_count = len(data.get("malware", []))
    reputation = data.get("reputation", 0)
    score = min(pulse_count * 10 + malware_count * 20 + reputation, 100)
    return round(score)

def standardize_ibmxforce(result, indicator=None):
    # Safely extract the score and categories from the result
    score = result.get("score", 0)
    categories = result.get("categoryDescriptions", [])

    # You can add logging or print statements to inspect the data if the issue persists
    if score == 0:
        print(f"Warning: Missing or zero score for indicator: {indicator}")
    if not categories:
        print(f"Warning: No categories found for indicator: {indicator}")
    
    # Return the standardized data
    return {
        "module": "ibmxforce",
        "indicator": indicator or result.get("indicator"),
        "risk_score": score,
        "summary": {
            "score": score,
            "categories": categories
        },
        "raw": result
    }

def calculate_ibmxforce_score(data):
    return int(data.get("score", 0))


def standardize_shodan(result, indicator=None):
    if not isinstance(result, dict) or "error" in result:
        return {
            "module": "shodan",
            "indicator": indicator,
            "risk_score": "N/A",
            "summary": {"error": result.get("error") if isinstance(result, dict) else "Invalid format"},
            "raw": result
        }

    vulns = result.get("vulns", [])
    ports = result.get("ports", [])
    risk_score = min(len(vulns) * 10 + len(ports) * 2, 100)

    return {
        "module": "shodan",
        "indicator": result.get("ip_str", indicator),
        "risk_score": risk_score,
        "summary": {
            "vulns": vulns,
            "ports": ports
        },
        "raw": result
    }


def calculate_shodan_score(data):
    # Extract relevant data from the input
    vulns = data.get("vulns", [])
    ports = data.get("ports", [])
    hostnames = data.get("hostnames", [])
    os = data.get("os", "")
    location = data.get("location", {})
    
    # Assign different weight factors to each aspect
    vuln_weight = 10  # Each vulnerability gets a higher weight
    port_weight = 2  # Each open port has a lower weight
    hostname_weight = 1  # Each hostname provides additional points (lower weight)
    os_weight = 5  # OS information may indicate the likelihood of vulnerabilities
    location_weight = 3  # Location-specific risks may influence score

    # Calculate the score based on the weighted factors
    vuln_score = len(vulns) * vuln_weight
    port_score = len(ports) * port_weight
    hostname_score = len(hostnames) * hostname_weight
    os_score = 0
    if os:
        os_score = os_weight  # Consider OS as a factor, assigning it a fixed score if it exists
    location_score = 0
    if location.get('country', '') not in ['United States', 'Canada']:  # Example assumption: locations outside US/Canada may have higher risk
        location_score = location_weight

    # Sum all the scores
    total_score = vuln_score + port_score + hostname_score + os_score + location_score

    # Cap the score at 100
    return min(total_score, 100)

def standardize_apivoid(result, indicator=None):
    data = result.get("data", {})  # <--- FIX
    services = data.get("services", [])
    vulnerabilities = data.get("vulnerabilities", [])
    threat_score = data.get("threat_score", 0)

    risk_score = min(threat_score + len(vulnerabilities) * 10 + len(services) * 5, 100)
    
    return {
        "module": "apivoid",
        "indicator": data.get("ip"),
        "risk_score": risk_score,
        "summary": {
            "services": services,
            "vulnerabilities": vulnerabilities
        },
        "raw": result
    }

def calculate_apivoid_score(data):
    services = data.get("services", [])
    vulnerabilities = data.get("vulnerabilities", [])
    threat_score = data.get("threat_score", 0)
    
    # Risk score calculation based on services, vulnerabilities, and threat_score
    return min(threat_score + len(vulnerabilities) * 10 + len(services) * 5, 100)


def standardize_greynoise(result, indicator=None):
    if not isinstance(result, dict):
        return None

    # If message indicates a failure or no result, return "N/A"
    if result.get("message", "").lower() != "success":
        return {
            "module": "greynoise",
            "indicator": indicator,
            "risk_score": "N/A",
            "summary": {
                "error": result.get("message", "Unknown error")
            },
            "raw": result
        }

    classification = result.get("classification", "unknown")
    tags = result.get("tags", [])
    risk_score = calculate_greynoise_score(result)

    return {
        "module": "greynoise",
        "indicator": result.get("ip", indicator),
        "risk_score": risk_score,
        "summary": {
            "classification": classification,
            "tags": tags
        },
        "raw": result
    }


def calculate_greynoise_score(data):
    classification = data.get("classification", "").lower()
    return {
        "malicious": 90,
        "unknown": 50,
        "benign": 0
    }.get(classification, 0)


def standardize_urlscan(result, indicator=None):
    verdicts = result.get("verdicts", {})
    score = result.get("score", 0)
    risk_score = score
    return {
        "module": "urlscan",
        "indicator": result.get("url"),
        "risk_score": risk_score,
        "summary": {
            "verdicts": verdicts,
            "score": score
        },
        "raw": result
    }

def calculate_urlscan_score(data):
    return int(data.get("score", 0))


def standardize_threatfox_score(result, indicator=None):
    if not isinstance(result, dict):
        return {
            "module": "threatfox",
            "indicator": indicator,
            "risk_score": "N/A",
            "summary": {"error": "Invalid format"},
            "raw": result
        }

    # Handle known benign case: no results for the indicator
    if result.get("query_status") == "no_results" or result.get("error") == "No results found for the given indicator":
        return {
            "module": "threatfox",
            "indicator": indicator,
            "risk_score": 0,  # Benign
            "summary": {"note": "No results found for the given indicator"},
            "raw": result
        }

    # Handle all other errors
    if "error" in result:
        return {
            "module": "threatfox",
            "indicator": indicator,
            "risk_score": "N/A",
            "summary": {"error": result["error"]},
            "raw": result
        }

    data = result.get("data", [])
    if not data or not isinstance(data, list) or not isinstance(data[0], dict):
        return {
            "module": "threatfox",
            "indicator": indicator,
            "risk_score": "N/A",
            "summary": {"error": "No valid data"},
            "raw": result
        }

    data_item = data[0]
    indicator = indicator or data_item.get("ioc")
    risk_score = calculate_threatfox_score(data_item)

    return {
        "module": "threatfox",
        "indicator": indicator,
        "risk_score": risk_score,
        "summary": {
            "threat_type": data_item.get("threat_type"),
            "confidence": data_item.get("confidence_level", 0),
            "tags": data_item.get("tags", []),
            "reference": data_item.get("reference"),
        },
        "raw": result,
    }

def calculate_threatfox_score(data):
    confidence = int(data.get("confidence_level", 0))
    threat_type = data.get("threat_type", "").lower()
    malware_name = (data.get("malware") or "").lower()
    malware_aliases = (data.get("malware_alias") or "").lower()
    tags = [tag.lower() for tag in data.get("tags", [])]

    # Base score - if ThreatFox knows about it, it starts risky
    base_score = 50

    # High-risk threat types
    high_risk_types = [
        "botnet_cc", "malware_download", "payload_delivery", "c2", "exploit", "ransomware",
        "keylogger", "stealer", "rat", "banking_trojan", "loader"
    ]
    if threat_type in high_risk_types:
        base_score += 25

    # Risky malware names (expanded list)
    risky_malware = [
        "cobalt_strike", "emotet", "trickbot", "agent_tesla", "quakbot", "qbot",
        "raccoon", "redline", "lokibot", "zeus", "remcos", "njrat",
        "blackbasta", "lockbit", "clop", "conti", "blackcat", "alphv", "darkside"
    ]
    if any(m in malware_name for m in risky_malware) or any(m in malware_aliases for m in risky_malware):
        base_score += 30

    # Risky tags (expanded)
    risky_tags = [
        "apt", "cobaltstrike", "beacon", "exploit-kit", "loader", "stealer",
        "banker", "ransomware", "keylogger", "rat", "remote-access-trojan",
        "botnet", "infostealer"
    ]
    if any(tag in risky_tags for tag in tags):
        base_score += 20

    # Reduce score slightly for "less risky" categories (adware, miners)
    low_risk_tags = ["adware", "miner", "crypto-miner"]
    if any(tag in low_risk_tags for tag in tags):
        base_score -= 15

    # Cap the base score between 0 and 100
    base_score = max(0, min(base_score, 100))

    # Apply confidence weighting
    final_score = base_score * (confidence / 100)

    # Round and ensure the final score is max 100
    return round(min(final_score, 100))


def handle_malwarebazaar_response(response_json):
    print(f"Response status: {response_json.get('query_status')}")
    if response_json.get("query_status") != "ok":
        return {"error": "MalwareBazaar query failed", "raw": response_json}

    results = []
    data = response_json.get("data", [])
    print(f"Found {len(data)} records from MalwareBazaar.")

    for result in data:
        standardized = standardize_malwarebazaar_score([result])
        print(f"Standardized result: {standardized}")
        results.append(standardized)

    return results


def standardize_malwarebazaar_score(result, indicator=None):
    if isinstance(result, str):
        print("Error: Received a string instead of a dictionary")
        return {"error": f"Expected a dictionary, but received a string: {result}"}

    data = result[0] if isinstance(result, list) and result else {}
    print("Data from MalwareBazaar:", data)

    indicator = indicator or data.get("sha256_hash")
    malware_family = data.get("signature", "unknown")
    tags = data.get("tags", [])
    file_type = data.get("file_type", "unknown")

    risk_score = calculate_malwarebazaar_score(data)

    return {
        "module": "malwarebazaar",
        "indicator": indicator,
        "risk_score": risk_score,
        "summary": {
            "malware_family": malware_family,
            "file_type": file_type,
            "tags": tags,
            "source": data.get("origin", "unknown"),
        },
        "raw": result
    }

def calculate_malwarebazaar_score(data):
    score = 0
    malware_family = (data.get("signature") or "").lower()
    tags = [tag.lower() for tag in data.get("tags", [])]

    # Apply scoring based on known malware families
    family_keywords = ["emotet", "qakbot", "cobalt strike", "lokibot", "netwire"]
    score += sum(40 for family in family_keywords if family in malware_family)

    # Tags scoring
    tag_keywords = ["apt", "loader", "stealer", "keylogger", "ransomware"]
    score += sum(30 for tag in tags if tag in tag_keywords)

    # Source scoring
    source_keywords = ["tide", "internal", "vendor"]
    score += sum(20 for source in source_keywords if data.get("origin", "").lower() == source)

    return min(score, 100)

def standardize_urlhaus_score(match: list, indicator: str) -> dict:
    found = bool(match)
    return {
        "module": "urlhaus",
        "indicator": indicator,
        "risk_score": 100 if found else 0,
        "summary": {
            "match_count": len(match),
            "threat_types": list({m.get("threat") for m in match if m.get("threat")}),
            "source": "Offline URLHaus feed",
            "confidence": "high" if found else "none"
        },
        "raw": match
    }

def calculate_urlhaus_score(data):
    score = 0
    tags = [tag.lower() for tag in data.get("tags", [])]
    threat_type = data.get("threat", "").lower()

    # Apply scoring based on threat types and tags
    high_risk_threats = ["malware_download", "exploit", "phishing"]
    risky_tags = ["c2", "payload", "ransomware", "drive-by"]

    if threat_type in high_risk_threats:
        score += 40

    if any(tag in risky_tags for tag in tags):
        score += 30

    # Increase score if it's from trusted reporter sources
    if data.get("reporter", "").lower() in ["urlscan", "internal", "certgov"]:
        score += 20

    return min(score, 100)


def handle_phishtank_response(response_json):
    # Basic validation: Check if 'data' exists and is a valid dictionary
    if 'data' not in response_json or not isinstance(response_json['data'], dict):
        return {"error": "Missing or invalid 'data' in PhishTank response", "raw": response_json}

    # Standardize the data
    standardized = standardize_phishtank_score(response_json['data'])
    return [standardized]


def standardize_phishtank_score(result, indicator=None):
    # Error handling: check if result is a valid dictionary
    if isinstance(result, str):
        return {"error": f"Expected a dictionary, but received a string: {result}", "raw": result}

    if not isinstance(result, dict):
        return {"error": "PhishTank result is not a valid dictionary", "raw": result}

    # Extracting relevant fields from the response data
    indicator = result.get("url", indicator)
    submission_time = result.get("submission_time", "unknown")
    verified = result.get("verified", False)

    # Calculating risk score based on the verification status and submission time
    risk_score = calculate_phishtank_score(result)

    return {
        "module": "phishtank",
        "indicator": indicator,
        "risk_score": risk_score,
        "summary": {
            "verified": verified,
            "submission_time": submission_time,
        },
        "raw": result
    }


def calculate_phishtank_score(data):
    # Mapping verification status to risk scores
    verified = data.get("verified", False)
    submission_time = data.get("submission_time", "")

    # A higher risk score for verified phish, with the potential for further enhancements based on time of submission
    score = 0
    if verified:
        score += 80  # Verified phishing URLs are considered high-risk
    if submission_time:
        # If submission time is within the last 30 days, increase the score
        from datetime import datetime, timedelta

        submission_date = datetime.strptime(submission_time, "%Y-%m-%d")
        if submission_date > datetime.now() - timedelta(days=30):
            score += 10  # Recent submission = higher risk

    return min(score, 100)

def handle_onionoo_response(response_json):
    # Basic validation
    if 'relays' not in response_json:
        return {"error": "Missing 'relays' in Onionoo response", "raw": response_json}

    standardized_results = []
    for relay in response_json.get("relays", []):
        standardized_results.append(standardize_onionoo(relay))

    return standardized_results


def standardize_onionoo(result, indicator=None):
    fingerprint = result.get("fingerprint")
    nickname = result.get("nickname", "unknown")
    flags = result.get("flags", [])
    contact = result.get("contact", "unknown")
    hostname = result.get("or_addresses", ["unknown"])[0]

    risk_score = calculate_onionoo_score(result)

    return {
        "module": "onionoo",
        "indicator": fingerprint or hostname,
        "risk_score": risk_score,
        "summary": {
            "nickname": nickname,
            "flags": flags,
            "contact": contact,
            "country": result.get("country", "unknown"),
            "host": hostname,
        },
        "raw": result
    }


def calculate_onionoo_score(data):
    score = 0
    flags = [flag.lower() for flag in data.get("flags", [])]
    contact = data.get("contact", "").lower()
    bandwidth = data.get("advertised_bandwidth", 0)

    if "badexit" in flags:
        score += 50
    elif "exit" in flags:
        score += 40
    elif "guard" in flags:
        score += 20

    if bandwidth > 10000000:
        score += 20

    if not contact and any(f in flags for f in ("exit", "badexit", "guard")):
        score += 10

    return min(score, 100)


def standardize_openphish_score(match: str, indicator: str) -> dict:
    return {
        "module": "openphish",
        "indicator": indicator,
        "risk_score": 100,
        "summary": {
            "match": match,
            "source": "OpenPhish feed",
            "confidence": "high"
        },
        "raw": match
    }

def standardize_cins_score(match: list, indicator: str) -> dict:
    found = bool(match)
    return {
        "module": "cinsscore",
        "indicator": indicator,
        "risk_score": 100 if found else 0,
        "summary": {
            "match": match,
            "source": "CINS Bad Guy IPs",
            "confidence": "high" if found else "none"
        },
        "raw": match
    }


def aggregate_results_for_user(user, indicator_results: list):
    """
    Takes a list of standardized result dicts per module and computes an overall risk score
    based on the user-specific module weights.
    """
    # Step 1: Build module:weight mapping for the user
    user_module_weights = {
        um.module.name.lower(): float(um.weight)
        for um in UserModule.objects.filter(user=user, enabled=True, module__enabled=True)
    }

    # Step 2: Ensure indicator_results is a list
    if not isinstance(indicator_results, list):
        logger.error(f"Expected a list for indicator_results, but got {type(indicator_results)}")
        return {"error": "Invalid data type for indicator_results"}

    # Step 3: Initialize module_scores
    module_scores = []

    # Step 4: Process the results
    for result in indicator_results:
        # Debugging: Log the type and contents of each result in the list
        logger.debug(f"Processing result: {result} (Type: {type(result)})")
        
        if isinstance(result, dict):
            module_name = result.get("module", "").lower()
            score = result.get("risk_score")

            # Check if both module_name and score are valid
            if module_name and isinstance(score, (int, float)):
                # If the module exists in user_module_weights, apply the corresponding weight
                if module_name in user_module_weights:
                    weighted_score = score * user_module_weights[module_name]
                    module_scores.append(weighted_score)  # Append valid score to module_scores
                else:
                    logger.warning(f"No weight found for module {module_name}. Skipping module scoring.")
            else:
                logger.warning(f"Invalid score or module for result: {result}")
        else:
            logger.error(f"Expected a dictionary for result, but got {type(result)}. Skipping.")

    # Step 5: If no valid module scores were found, return early
    if not module_scores:
        logger.error("No valid module scores found. Returning default error response.")
        return {"error": "No valid module scores found"}

    # Step 6: Compute the overall risk score
    overall_score = calculate_overall_risk_score(module_scores, user_module_weights)

    return {
        "results": indicator_results,
        "overall_score": overall_score
    }

def standardize_ipwhois_info(result, indicator=None):
    if not isinstance(result, dict):
        return {"error": "Invalid response format from IPWhois module", "raw": result}

    ip = result.get("ip", indicator)
    org = result.get("org", "unknown")
    country = result.get("country", "unknown")
    isp = result.get("isp", "unknown")
    type_ = result.get("type", "unknown")
    city = result.get("city", "unknown")
    region = result.get("region", "unknown")
    country_code = result.get("country_code", "unknown")
    asn = result.get("asn", "unknown")
    domain = result.get("domain", "unknown")
    
    return {
        "module": "ipwhois",
        "indicator": ip,
        "data": {
            "org": org,
            "isp": isp,
            "country": country,
            "city": city,
            "region": region,
            "country_code": country_code,
            "asn": asn,
            "domain": domain,
            "type": type_,
        },
        "raw": result
    }

STANDARDIZERS = {
    "abuseipdb": standardize_abuseipdb,
    "threatfox": standardize_threatfox_score,
    "virustotal": standardize_virustotal,
    "alienvault": standardize_alienvault,
    "ibmxforce": standardize_ibmxforce,
    "shodan": standardize_shodan,
    "malwarebazaar": standardize_malwarebazaar_score,
    "urlhaus": standardize_urlhaus_score,
    "apivoid": standardize_apivoid,
    "greynoise": standardize_greynoise,
    "urlscan": standardize_urlscan,
    "onionoo": standardize_onionoo,
    "openphish": standardize_openphish_score,
    "cinsscore": standardize_cins_score,
    "ipwhois": standardize_ipwhois_info,
}

RISK_SCORERS = {
    "abuseipdb": calculate_abuseipdb_score,
    "threatfox": calculate_threatfox_score,
    "virustotal": calculate_virustotal_score,
    "alienvault": calculate_alienvault_score,
    "ibmxforce": calculate_ibmxforce_score,
    "shodan": calculate_shodan_score,
    "malwarebazaar": calculate_malwarebazaar_score,
    "urlhaus": calculate_urlhaus_score,
    "apivoid": calculate_apivoid_score,
    "greynoise": calculate_greynoise_score,
    "urlscan": calculate_urlscan_score,
    "onionoo": calculate_onionoo_score,
}

