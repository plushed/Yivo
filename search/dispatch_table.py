from .queries import (
    VirusTotalQuery,
    AlienVaultQuery,
    IBMXForceQuery,
    CiscoTalosQuery,
    ShodanQuery,
    CensysQuery,
    AbuseIPDBQuery,
    GreyNoiseQuery,
    URLScanQuery,
    PhishLabsQuery,
)

# Dispatch table mapping module types to their respective query classes, supported indicator types, and weights
MODULE_QUERIES = {
    'VirusTotal': {
        'class': VirusTotalQuery,
        'supported_types': ['file', 'url', 'ip', 'domain'],
        'default_weight': 1.5,  # Example weight based on reputation
    },
    'AlienVault': {
        'class': AlienVaultQuery,
        'supported_types': ['file', 'url', 'ip', 'domain'],
        'default_weight': 1.2,
    },
    'IBM X-Force': {
        'class': IBMXForceQuery,
        'supported_types': ['file', 'url', 'ip', 'domain'],
        'default_weight': 1.0,
    },
    'Cisco Talos': {
        'class': CiscoTalosQuery,
        'supported_types': ['url', 'ip', 'domain'],
        'default_weight': 1.1,
    },
    'Shodan': {
        'class': ShodanQuery,
        'supported_types': ['ip'],
        'default_weight': 0.8,
    },
    'Censys': {
        'class': CensysQuery,
        'supported_types': ['ip', 'domain'],
        'default_weight': 0.9,
    },
    'AbuseIPDB': {
        'class': AbuseIPDBQuery,
        'supported_types': ['ip'],
        'default_weight': 0.7,
    },
    'GreyNoise': {
        'class': GreyNoiseQuery,
        'supported_types': ['ip'],
        'default_weight': 0.6,
    },
    'URLScan': {
        'class': URLScanQuery,
        'supported_types': ['url'],
        'default_weight': 1.3,
    },
    'PhishLabs': {
        'class': PhishLabsQuery,
        'supported_types': ['url', 'domain'],
        'default_weight': 0.9,
    },
}
