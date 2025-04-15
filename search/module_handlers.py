# search/module_handlers.py

def standardize_abuseipdb(result):
    return {
        "module": "abuseipdb",
        "indicator": result.get("ipAddress"),
        "risk_score": calculate_abuseipdb_score(result),
        "summary": {
            "abuseConfidenceScore": result.get("abuseConfidenceScore"),
            "totalReports": result.get("totalReports"),
            "isTor": result.get("isTor"),
            "countryCode": result.get("countryCode"),
            "domain": result.get("domain"),
        },
        "raw": result,
    }


def calculate_abuseipdb_score(data):
    return min(data.get("abuseConfidenceScore", 0), 100)

def standardize_virustotal(result, original_indicator=None):
    stats = result.get("last_analysis_stats", {})
    return {
        "module": "virustotal",
        "indicator": original_indicator or result.get("id", "unknown"),
        "risk_score": calculate_virustotal_score(result),
        "summary": {
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "undetected": stats.get("undetected"),
            "harmless": stats.get("harmless"),
            "reputation": result.get("reputation", None),
        },
        "raw": result,
    }

def calculate_virustotal_score(data):
    stats = data.get("last_analysis_stats", {})
    total = sum(stats.values())
    if total == 0:
        return 0
    score = (stats.get("malicious", 0) * 2 + stats.get("suspicious", 0)) / total * 100
    return round(score)

def standardize_alienvault(result):
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

def standardize_ibmxforce(result):
    score = result.get("score", 0)
    categories = result.get("categoryDescriptions", [])
    risk_score = score
    return {
        "module": "ibmxforce",
        "indicator": result.get("indicator"),
        "risk_score": risk_score,
        "summary": {
            "score": score,
            "categories": categories
        },
        "raw": result
    }

def calculate_ibmxforce_score(data):
    return int(data.get("score", 0))

def standardize_ciscotalos(result):
    threat_level = result.get("threat_level", "unknown")
    category = result.get("category", "unknown")
    risk_score = {"high": 90, "medium": 60, "low": 30}.get(threat_level.lower(), 0)
    return {
        "module": "ciscotalos",
        "indicator": result.get("indicator"),
        "risk_score": risk_score,
        "summary": {
            "threat_level": threat_level,
            "category": category
        },
        "raw": result
    }

def calculate_ciscotalos_score(data):
    threat_level = data.get("threat_level", "").lower()
    return {"high": 90, "medium": 60, "low": 30}.get(threat_level, 0)

def standardize_shodan(result):
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
    vulns = data.get("vulns", [])
    ports = data.get("ports", [])
    return min(len(vulns) * 10 + len(ports) * 2, 100)

def standardize_censys(result):
    services = result.get("services", [])
    vulnerabilities = result.get("vulnerabilities", [])
    risk_score = min(len(vulnerabilities) * 15 + len(services) * 5, 100)
    return {
        "module": "censys",
        "indicator": result.get("ip"),
        "risk_score": risk_score,
        "summary": {
            "services": services,
            "vulnerabilities": vulnerabilities
        },
        "raw": result
    }

def calculate_censys_score(data):
    services = data.get("services", [])
    vulnerabilities = data.get("vulnerabilities", [])
    return min(len(vulnerabilities) * 15 + len(services) * 5, 100)

def standardize_greynoise(result):
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

def standardize_urlscan(result):
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

def standardize_phishlabs(result):
    threat_level = result.get("threat_level", "unknown")
    category = result.get("category", "unknown")
    risk_score = {"high": 90, "medium": 60, "low": 30}.get(threat_level.lower(), 0)
    return {
        "module": "phishlabs",
        "indicator": result.get("indicator"),
        "risk_score": risk_score,
        "summary": {
            "threat_level": threat_level,
            "category": category
        },
        "raw": result
    }

def calculate_phishlabs_score(data):
    threat_level = data.get("threat_level", "").lower()
    return {"high": 90, "medium": 60, "low": 30}.get(threat_level, 0)

STANDARDIZERS = {
    "abuseipdb": standardize_abuseipdb,
    "virustotal": standardize_virustotal,
    "alienvault": standardize_alienvault,
    "ibmxforce": standardize_ibmxforce,
    "ciscotalos": standardize_ciscotalos,
    "shodan": standardize_shodan,
    "censys": standardize_censys,
    "greynoise": standardize_greynoise,
    "urlscan": standardize_urlscan,
    "phishlabs": standardize_phishlabs,
}

RISK_SCORERS = {
    "abuseipdb": calculate_abuseipdb_score,
    "virustotal": calculate_virustotal_score,
    "alienvault": calculate_alienvault_score,
    "ibmxforce": calculate_ibmxforce_score,
    "ciscotalos": calculate_ciscotalos_score,
    "shodan": calculate_shodan_score,
    "censys": calculate_censys_score,
    "greynoise": calculate_greynoise_score,
    "urlscan": calculate_urlscan_score,
    "phishlabs": calculate_phishlabs_score,
}

