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
    PhishLabsQuery
)

# Dispatch table mapping module types to their respective query classes
MODULE_QUERIES = {
    'VirusTotal': VirusTotalQuery,
    'AlienVault': AlienVaultQuery,
    'IBM X-Force': IBMXForceQuery,
    'Cisco Talos': CiscoTalosQuery,
    'Shodan': ShodanQuery,
    'Censys': CensysQuery,
    'AbuseIPDB': AbuseIPDBQuery,  
    'GreyNoise': GreyNoiseQuery, 
    'IPinfo': IPinfoQuery,        
    'URLScan': URLScanQuery,    
    'PhishLabs': PhishLabsQuery  
}