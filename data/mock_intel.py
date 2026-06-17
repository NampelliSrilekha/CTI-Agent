# data/mock_intel.py
# This simulates what VirusTotal, AbuseIPDB, etc. would return.
# Think of it as a frozen snapshot of real threat intel.

MOCK_IPS = {
    "45.83.122.10": {
        "malicious": True,
        "confidence": 0.95,
        "abuse_score": 87,
        "country": "RU",
        "asn": "AS197695 REG.RU",
        "isp": "Reg.Ru",
        "tags": ["port-scanner", "brute-force", "c2"],
        "last_seen": "2025-06-01",
        "related_domains": ["malware-drop.ru", "c2panel.xyz"],
        "reports": 142,
        "source": "AbuseIPDB (mock)"
    },
    "8.8.8.8": {
        "malicious": False,
        "confidence": 0.99,
        "abuse_score": 0,
        "country": "US",
        "asn": "AS15169 Google LLC",
        "isp": "Google",
        "tags": ["dns-resolver"],
        "last_seen": None,
        "related_domains": [],
        "reports": 0,
        "source": "AbuseIPDB (mock)"
    },
    "185.220.101.45": {
        "malicious": True,
        "confidence": 0.91,
        "abuse_score": 100,
        "country": "DE",
        "asn": "AS60729 Bravura Software",
        "isp": "Tor Exit Node Operator",
        "tags": ["tor-exit-node", "c2", "ransomware-delivery"],
        "last_seen": "2025-06-10",
        "related_domains": ["darkpanel.onion.pet", "exfil-drop.io"],
        "reports": 891,
        "source": "AbuseIPDB (mock)"
    }
}

MOCK_DOMAINS = {
    "malware-drop.ru": {
        "malicious": True,
        "confidence": 0.97,
        "categories": ["malware", "phishing"],
        "registrar": "REG.RU",
        "created": "2024-11-15",
        "related_ips": ["45.83.122.10"],
        "vt_detections": "58/90",
        "source": "VirusTotal (mock)"
    },
    "google.com": {
        "malicious": False,
        "confidence": 0.99,
        "categories": ["search-engine", "trusted"],
        "registrar": "MarkMonitor",
        "created": "1997-09-15",
        "related_ips": ["142.250.80.46"],
        "vt_detections": "0/90",
        "source": "VirusTotal (mock)"
    },
    "c2panel.xyz": {
        "malicious": True,
        "confidence": 0.93,
        "categories": ["c2", "botnet"],
        "registrar": "Namecheap",
        "created": "2025-01-03",
        "related_ips": ["45.83.122.10", "185.220.101.45"],
        "vt_detections": "71/90",
        "source": "VirusTotal (mock)"
    }
}

MOCK_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": {
        "malicious": True,
        "confidence": 0.99,
        "file_type": "PE32 executable",
        "file_name": "invoice_april.exe",
        "family": "Emotet",
        "vt_detections": "67/72",
        "size_kb": 412,
        "first_seen": "2024-08-20",
        "tags": ["trojan", "banker", "emotet", "loader"],
        "source": "VirusTotal (mock)"
    }
}

MOCK_THREAT_ACTORS = {
    "apt29": {
        "aliases": ["Cozy Bear", "The Dukes", "Midnight Blizzard"],
        "origin": "Russia",
        "sponsored_by": "SVR (Russian Foreign Intelligence)",
        "active_since": "2008",
        "targets": ["government", "think-tanks", "healthcare", "energy"],
        "ttps": [
            {"id": "T1566.001", "name": "Spearphishing Attachment"},
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1059.001", "name": "PowerShell"},
            {"id": "T1071.001", "name": "Web Protocols (C2)"},
            {"id": "T1027", "name": "Obfuscated Files or Information"},
            {"id": "T1003", "name": "OS Credential Dumping"},
        ],
        "notable_campaigns": ["SolarWinds (2020)", "Microsoft breach (2024)"],
        "source": "MITRE ATT&CK (mock)"
    },
    "apt28": {
        "aliases": ["Fancy Bear", "Sofacy", "Forest Blizzard"],
        "origin": "Russia",
        "sponsored_by": "GRU (Russian Military Intelligence)",
        "active_since": "2004",
        "targets": ["military", "government", "aerospace", "media"],
        "ttps": [
            {"id": "T1566.002", "name": "Spearphishing Link"},
            {"id": "T1203", "name": "Exploitation for Client Execution"},
            {"id": "T1056.001", "name": "Keylogging"},
            {"id": "T1105", "name": "Ingress Tool Transfer"},
        ],
        "notable_campaigns": ["DNC Hack (2016)", "French Election (2017)"],
        "source": "MITRE ATT&CK (mock)"
    },
    "lazarus": {
        "aliases": ["Lazarus Group", "Hidden Cobra", "Zinc"],
        "origin": "North Korea",
        "sponsored_by": "RGB (Reconnaissance General Bureau)",
        "active_since": "2009",
        "targets": ["financial", "crypto", "defense", "media"],
        "ttps": [
            {"id": "T1566.001", "name": "Spearphishing Attachment"},
            {"id": "T1486", "name": "Data Encrypted for Impact (Ransomware)"},
            {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            {"id": "T1204.002", "name": "Malicious File Execution"},
        ],
        "notable_campaigns": ["WannaCry (2017)", "Bybit crypto theft (2025)"],
        "source": "MITRE ATT&CK (mock)"
    }
}

MOCK_CVES = {
    "confluence": {
        "7.13": [
            {
                "cve_id": "CVE-2022-26134",
                "cvss": 9.8,
                "severity": "CRITICAL",
                "description": "OGNL injection RCE — unauthenticated remote code execution.",
                "patch_version": "7.13.7+",
                "exploited_in_wild": True,
                "exploit_available": True,
                "threat_actors": ["APT41", "multiple ransomware groups"],
                "source": "NVD (mock)"
            },
            {
                "cve_id": "CVE-2023-22518",
                "cvss": 9.1,
                "severity": "CRITICAL",
                "description": "Improper authorization — allows full data destruction.",
                "patch_version": "7.13.20+",
                "exploited_in_wild": True,
                "exploit_available": True,
                "threat_actors": ["Cerber ransomware"],
                "source": "NVD (mock)"
            }
        ]
    },
    "log4j": {
        "2.14": [
            {
                "cve_id": "CVE-2021-44228",
                "cvss": 10.0,
                "severity": "CRITICAL",
                "description": "Log4Shell — JNDI injection leading to RCE.",
                "patch_version": "2.15.0+",
                "exploited_in_wild": True,
                "exploit_available": True,
                "threat_actors": ["APT41", "APT35", "multiple ransomware groups"],
                "source": "NVD (mock)"
            }
        ]
    }
}