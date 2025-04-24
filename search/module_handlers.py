# search/module_handlers.py
import logging

# Initialize the logger
logger = logging.getLogger(__name__)

def standardize_abuseipdb(result, indicator=None):
    # Access the nested 'data' key and extract the 'ipAddress'
    data = result.get("data", {})  # Retrieve the entire 'data' block
    
    ip_address = data.get("ipAddress")  # Safely retrieve the ipAddress
    
    # Now pass the 'data' object to the score calculation function
    risk_score = calculate_abuseipdb_score(data)
    
    return {
        "module": "abuseipdb",
        "indicator": ip_address,  # Use the extracted IP address here
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
    # Fetch the relevant fields from the response
    data = result.get("data", {})
    attributes = data.get("attributes", {})

    # Extract the summary stats from last_analysis_stats
    last_analysis_stats = attributes.get("last_analysis_stats", {})
    
    # Set the default values for the summary fields
    malicious = last_analysis_stats.get("malicious", 0)
    suspicious = last_analysis_stats.get("suspicious", 0)
    undetected = last_analysis_stats.get("undetected", 0)
    harmless = last_analysis_stats.get("harmless", 0)
    reputation = attributes.get("reputation", 0)

    # Include total_votes as part of the result
    total_votes = attributes.get("total_votes", {})
    total_malicious = total_votes.get("malicious", 0)
    total_harmless = total_votes.get("harmless", 0)

    # Now, calculate the risk score based on the updated summary and votes
    return {
        "module": "virustotal",
        "indicator": original_indicator or data.get("id", "unknown"),
        "risk_score": calculate_virustotal_score(last_analysis_stats),  # Calculate from last_analysis_stats
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
    # We calculate based on the last_analysis_stats (malicious, suspicious, undetected, harmless)
    total = sum([last_analysis_stats.get(key, 0) for key in ["malicious", "suspicious", "undetected", "harmless"]])
    
    if total == 0:
        return 0

    # Let's consider that 'malicious' and 'suspicious' are weighted more heavily in the risk score
    score = (last_analysis_stats.get("malicious", 0) * 5 + last_analysis_stats.get("suspicious", 0)) / total * 100
    return round(score)



def standardize_alienvault(result, indicator=None):
    pulse_count = result.get("pulse_info", {}).get("count", 0)
    malware = result.get("malware", [])
    reputation = result.get("reputation", 0)
    risk_score = min(pulse_count * 10 + len(malware) * 20 + reputation, 100)
    return {
        "module": "alienvault",
        "indicator": result.get("indicator"),
        "risk_score": risk_score,
        "summary": {
            "pulse_count": pulse_count,
            "malware_count": len(malware),
            "reputation": reputation
        },
        "raw": result
    }

def calculate_alienvault_score(data):
    pulse_count = data.get("pulse_info", {}).get("count", 0)
    malware = len(data.get("malware", []))
    reputation = data.get("reputation", 0)
    score = min(pulse_count * 10 + malware * 20 + reputation, 100)
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
    vulns = result.get("vulns", [])
    ports = result.get("ports", [])
    risk_score = min(len(vulns) * 10 + len(ports) * 2, 100)
    return {
        "module": "shodan",
        "indicator": result.get("ip_str"),
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
    # Extracting relevant data from the apivoid response
    services = result.get("services", [])
    vulnerabilities = result.get("vulnerabilities", [])
    threat_score = result.get("threat_score", 0)  # Assuming 'threat_score' is part of the response

    # Calculating the risk score using a different method, if applicable
    risk_score = min(threat_score + len(vulnerabilities) * 10 + len(services) * 5, 100)
    
    return {
        "module": "apivoid",
        "indicator": result.get("ip"),
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
    classification = result.get("classification", "unknown")
    tags = result.get("tags", [])
    risk_score = {"malicious": 90, "benign": 10, "unknown": 50}.get(classification.lower(), 50)
    return {
        "module": "greynoise",
        "indicator": result.get("ip"),
        "risk_score": risk_score,
        "summary": {
            "classification": classification,
            "tags": tags
        },
        "raw": result
    }

def calculate_greynoise_score(data):
    classification = data.get("classification", "").lower()
    return {"malicious": 90, "unknown": 50, "benign": 10}.get(classification, 50)

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


def handle_threatfox_response(response_json):
    # Check the overall response status
    print(f"Response status: {response_json.get('query_status')}")
    
    if response_json.get("query_status") != "ok":
        return {"error": "ThreatFox query failed", "raw": response_json}

    # Get the indicators
    indicators = response_json.get("data", [])
    print(f"Found {len(indicators)} indicators.")
    
    if not indicators:
        return {"error": "No data found", "raw": response_json}

    results = []
    for indicator in indicators:
        print(f"Processing indicator: {indicator.get('ioc')}")
        # Call standardize function with the correct indicator data
        result = standardize_threatfox_score(indicator)
        print(f"Standardized result: {result}")
        results.append(result)

    return results


def standardize_threatfox_score(result, indicator=None):
    # Check the result type before processing
    if isinstance(result, str):
        print("Error: Received a string instead of a dictionary")
        return {"error": f"Expected a dictionary, but received a string: {result}"}
    
    # If result is a dictionary, proceed
    data = result.get('data', [])[0] if result.get('data') else {}

    # Debugging: Print the 'data' object and its type
    print("Data from result:", data)
    print("Type of data:", type(data))

    # Ensure `ioc` is being passed correctly
    indicator = data.get("ioc", indicator)
    
    threat_type = data.get("ioc_type", "unknown")
    confidence = int(data.get("confidence_level", 0))
    tags = data.get("tags", [])
    
    risk_score = calculate_threatfox_score(data)

    return {
        "module": "threatfox",
        "indicator": indicator,
        "risk_score": risk_score,
        "summary": {
            "threat_type": threat_type,
            "confidence": confidence,
            "tags": tags,
            "reference": data.get("reference"),
        },
        "raw": result
    }



def calculate_threatfox_score(data):
    # Extract data for easier reference
    confidence = int(data.get("confidence_level", 0))
    threat_type = data.get("threat_type", "").lower()
    malware_name = (data.get("malware") or "").lower()
    malware_aliases = (data.get("malware_alias") or "").lower()
    tags = [tag.lower() for tag in data.get("tags", [])]
    
    # Base score starts at 0
    base_score = 0
    
    # Adjust base score based on threat type
    high_risk_types = ["botnet_cc", "malware_download", "c2", "exploit"]
    if threat_type in high_risk_types:
        base_score += 30  # High-risk threat type

    # Add points if malware is a known risky malware
    risky_malware = ["cobalt_strike", "emotet", "trickbot", "agent_tesla", "quakbot"]
    if any(m in malware_name for m in risky_malware):
        base_score += 40  # Risky malware
    
    # Add points for risky tags
    risky_tags = ["apt", "cobaltstrike", "beacon", "exploit-kit", "loader"]
    if any(tag in risky_tags for tag in tags):
        base_score += 20  # Risky tag

    # Cap the base score at 100 (can't go higher than that)
    base_score = min(base_score, 100)

    # Now apply confidence to increase or decrease the final score
    # If confidence is high (e.g., 100), the score stays the same or increases
    final_score = base_score * (confidence / 100)

    # Round the final score to avoid decimals and cap at 100
    final_score = round(min(final_score, 100))

    return final_score

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

def handle_urlhaus_response(response_json):
    # Debugging: Print out the response type and raw content for inspection
    print(f"Response type: {type(response_json)}")
    print(f"Raw result: {response_json}")

    # Check if the response contains an error field
    if 'error' in response_json:
        return {"error": response_json['error'], "raw": response_json}

    # Check for the 'data' field and if it is valid
    if 'data' not in response_json or not isinstance(response_json['data'], dict):
        return {"error": "Missing or invalid 'data' field in URLHaus response", "raw": response_json}

    # If response structure is correct, proceed with standardization
    data = response_json.get("data", {})
    standardized = standardize_urlhaus_score(data)
    print(f"Standardized result: {standardized}")
    return [standardized]


def standardize_urlhaus_score(result, indicator=None):
    if isinstance(result, str):
        print(f"Error: Received a string instead of a dictionary - {result}")
        return {"error": f"Expected a dictionary, but received a string: {result}"}

    if not isinstance(result, dict):
        return {"error": "URLHaus result is not a valid dictionary", "raw": result}
    
    indicator = result.get("url", indicator)
    tags = result.get("tags", [])
    threat_type = result.get("threat", "unknown")
    reporter = result.get("reporter", "unknown")

    # Calculate risk score based on the data
    risk_score = calculate_urlhaus_score(result)

    return {
        "module": "urlhaus",
        "indicator": indicator,
        "risk_score": risk_score,
        "summary": {
            "threat_type": threat_type,
            "tags": tags,
            "reporter": reporter,
            "reference": result.get("urlhaus_reference", ""),
        },
        "raw": result
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

    if "exit" in flags:
        score += 40
    elif "guard" in flags:
        score += 20
    if bandwidth > 10000000:  # >10MBps could be considered high bandwidth
        score += 20
    if not contact:
        score += 10
    if "badexit" in flags:
        score += 30

    return min(score, 100)

# search/modules/builtin/handlers.py

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

def standardize_cins_score(match: str, indicator: str) -> dict:
    return {
        "module": "cins",
        "indicator": indicator,
        "risk_score": 100,
        "summary": {
            "match": match,
            "source": "CINS Bad Guy IPs",
            "confidence": "high"
        },
        "raw": match
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
    "cins": standardize_cins_score,
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

