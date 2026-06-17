# agent/tools.py
# Real API integrations with:
#   - Rate limit handling (429 errors)
#   - Graceful fallback when data is missing
#   - Source attribution on every result
#   - Async calls (faster — multiple APIs in parallel where possible)

import os
import json
import asyncio
import aiohttp
import shodan
from OTXv2 import OTXv2, IndicatorTypes

# ── Load API keys from environment ────────────────────────────
VT_KEY       = os.environ.get("VIRUSTOTAL_API_KEY")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY")
OTX_KEY      = os.environ.get("OTX_API_KEY")
NVD_KEY      = os.environ.get("NVD_API_KEY")
SHODAN_KEY   = os.environ.get("SHODAN_API_KEY")


# ══════════════════════════════════════════════════════════════
# TOOL SCHEMAS  (what Claude reads to decide which tool to call)
# ══════════════════════════════════════════════════════════════

TOOL_SCHEMAS = [
    {
        "name": "lookup_ip",
        "description": (
            "Look up the reputation and threat data for an IP address. "
            "Queries AbuseIPDB for abuse score and reports, VirusTotal for "
            "malicious verdicts, and Shodan for open ports and services. "
            "Use when an analyst asks if an IP is malicious, suspicious, or safe."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "The IPv4 or IPv6 address to look up, e.g. '45.83.122.10'."
                }
            },
            "required": ["ip"]
        }
    },
    {
        "name": "lookup_domain",
        "description": (
            "Look up the reputation of a domain name. "
            "Queries VirusTotal for malicious detections and OTX for threat pulses. "
            "Use when an analyst asks about a domain or URL."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The domain to look up, e.g. 'malware-drop.ru'."
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "lookup_hash",
        "description": (
            "Look up a file hash (MD5, SHA1, or SHA256) on VirusTotal. "
            "Returns detection ratio, file type, malware family if known. "
            "Use when an analyst provides a hash and wants to know if the file is malicious."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hash": {
                    "type": "string",
                    "description": "The file hash to look up."
                }
            },
            "required": ["hash"]
        }
    },
    {
        "name": "get_threat_actor",
        "description": (
            "Profile a known threat actor or APT group using AlienVault OTX. "
            "Returns aliases, TTPs, targeted sectors, and recent activity pulses. "
            "Use for questions like 'What is APT29?' or 'Tell me about Lazarus Group'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "actor_name": {
                    "type": "string",
                    "description": "Name or alias of the threat actor, e.g. 'APT29', 'Lazarus'."
                }
            },
            "required": ["actor_name"]
        }
    },
    {
        "name": "check_exposure",
        "description": (
            "Check if a software version has known CVEs using the NVD database. "
            "Returns CVE IDs, CVSS scores, severity, and whether exploited in the wild. "
            "Use when an analyst says 'We run X version Y — are we exposed?'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "software": {
                    "type": "string",
                    "description": "Software name, e.g. 'Confluence', 'Log4j', 'Apache'."
                },
                "version": {
                    "type": "string",
                    "description": "Version string, e.g. '7.13', '2.14.1'."
                }
            },
            "required": ["software", "version"]
        }
    },
    {
        "name": "pivot",
        "description": (
            "Pivot from a known IOC to discover related entities. "
            "From an IP: finds related domains and open ports via Shodan + VT. "
            "From a domain: finds related IPs and sibling domains via VT + OTX. "
            "Use when analyst says 'pivot from that IP' or 'find related domains'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc_type": {
                    "type": "string",
                    "enum": ["ip", "domain"],
                    "description": "Type of the starting IOC."
                },
                "value": {
                    "type": "string",
                    "description": "The IOC value to pivot from."
                }
            },
            "required": ["ioc_type", "value"]
        }
    }
]


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════

async def _vt_get(session: aiohttp.ClientSession, endpoint: str) -> dict:
    """
    Make a GET request to VirusTotal API v3.
    VirusTotal uses a simple x-apikey header for auth.
    Handles 404 (not found) and 429 (rate limit) gracefully.
    """
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    headers = {"x-apikey": VT_KEY}
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 404:
                return {"error": "not_found"}
            if resp.status == 429:
                return {"error": "rate_limited", "message": "VirusTotal rate limit hit. Try again in 60s."}
            if resp.status != 200:
                return {"error": f"http_{resp.status}"}
            return await resp.json()
    except asyncio.TimeoutError:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


async def _abuseipdb_get(session: aiohttp.ClientSession, ip: str) -> dict:
    """
    Query AbuseIPDB for an IP's abuse score.
    maxAgeInDays=90 means reports from the last 90 days.
    verbose=True includes each individual report.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    try:
        async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 429:
                return {"error": "rate_limited", "message": "AbuseIPDB rate limit hit."}
            if resp.status != 200:
                return {"error": f"http_{resp.status}"}
            return await resp.json()
    except asyncio.TimeoutError:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


async def _nvd_search(session: aiohttp.ClientSession, keyword: str) -> dict:
    """
    Search NVD (National Vulnerability Database) for CVEs matching a keyword.
    NVD returns paginated results — we take the first 5 most relevant.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": NVD_KEY}
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5,
        "startIndex": 0
    }
    try:
        async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 429:
                return {"error": "rate_limited", "message": "NVD rate limit hit. Wait 30 seconds."}
            if resp.status != 200:
                return {"error": f"http_{resp.status}"}
            return await resp.json()
    except asyncio.TimeoutError:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════
# TOOL IMPLEMENTATIONS
# ══════════════════════════════════════════════════════════════

async def _lookup_ip_async(ip: str) -> dict:
    """
    Calls AbuseIPDB + VirusTotal + Shodan in parallel for an IP.
    asyncio.gather() fires all 3 requests at the same time — 
    much faster than waiting for each one sequentially.
    """
    async with aiohttp.ClientSession() as session:
        # Fire all requests simultaneously
        abuse_task = _abuseipdb_get(session, ip)
        vt_task    = _vt_get(session, f"ip_addresses/{ip}")
        
        abuse_data, vt_data = await asyncio.gather(abuse_task, vt_task)

    result = {"ioc": ip, "type": "ip", "sources": []}

    # ── AbuseIPDB ─────────────────────────────────────────────
    if "error" not in abuse_data:
        d = abuse_data.get("data", {})
        result["abuse_score"]      = d.get("abuseConfidenceScore", 0)
        result["total_reports"]    = d.get("totalReports", 0)
        result["country"]          = d.get("countryCode", "Unknown")
        result["isp"]              = d.get("isp", "Unknown")
        result["domain"]           = d.get("domain", "Unknown")
        result["is_tor"]           = d.get("isTor", False)
        result["is_public"]        = d.get("isPublic", True)
        result["last_reported"]    = d.get("lastReportedAt")
        # Last 3 report categories for context
        reports = d.get("reports", [])[:3]
        result["recent_report_categories"] = [r.get("categories", []) for r in reports]
        result["sources"].append("AbuseIPDB")
    else:
        result["abuseipdb_error"] = abuse_data.get("message", abuse_data["error"])

    # ── VirusTotal ────────────────────────────────────────────
    if "error" not in vt_data:
        attrs = vt_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result["vt_malicious"]    = stats.get("malicious", 0)
        result["vt_suspicious"]   = stats.get("suspicious", 0)
        result["vt_harmless"]     = stats.get("harmless", 0)
        result["vt_total"]        = sum(stats.values())
        result["vt_verdict"]      = attrs.get("reputation", 0)
        result["network"]         = attrs.get("network", "Unknown")
        result["asn"]             = attrs.get("asn", "Unknown")
        result["as_owner"]        = attrs.get("as_owner", "Unknown")
        result["sources"].append("VirusTotal")
    else:
        result["virustotal_error"] = vt_data.get("message", vt_data["error"])

    # ── Shodan ────────────────────────────────────────────────
    # Shodan SDK is synchronous, so we run it outside the async context
    try:
        api = shodan.Shodan(SHODAN_KEY)
        host = api.host(ip)
        result["open_ports"]   = host.get("ports", [])
        result["hostnames"]    = host.get("hostnames", [])
        result["os"]           = host.get("os")
        result["tags"]         = host.get("tags", [])
        result["vulns"]        = list(host.get("vulns", {}).keys())
        result["org"]          = host.get("org")
        result["last_update"]  = host.get("last_update")
        # Summarize each service
        result["services"] = [
            {
                "port":    s.get("port"),
                "product": s.get("product"),
                "version": s.get("version"),
                "banner":  s.get("data", "")[:100]  # first 100 chars of banner
            }
            for s in host.get("data", [])[:5]  # top 5 services
        ]
        result["sources"].append("Shodan")
    except shodan.APIError as e:
        result["shodan_error"] = str(e)
    except Exception as e:
        result["shodan_error"] = str(e)

    # Overall verdict
    abuse_score = result.get("abuse_score", 0)
    vt_malicious = result.get("vt_malicious", 0)
    result["verdict"] = (
        "MALICIOUS" if (abuse_score > 50 or vt_malicious > 5) else
        "SUSPICIOUS" if (abuse_score > 20 or vt_malicious > 0) else
        "CLEAN"
    )
    result["confidence"] = round(
        min(1.0, (abuse_score / 100 * 0.5) + (min(vt_malicious, 20) / 20 * 0.5)), 2
    )

    return result


async def _lookup_domain_async(domain: str) -> dict:
    """Query VirusTotal + OTX for a domain."""
    async with aiohttp.ClientSession() as session:
        vt_data = await _vt_get(session, f"domains/{domain}")

    result = {"ioc": domain, "type": "domain", "sources": []}

    # ── VirusTotal ────────────────────────────────────────────
    if "error" not in vt_data:
        attrs = vt_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result["vt_malicious"]   = stats.get("malicious", 0)
        result["vt_suspicious"]  = stats.get("suspicious", 0)
        result["vt_total"]       = sum(stats.values())
        result["categories"]     = attrs.get("categories", {})
        result["registrar"]      = attrs.get("registrar")
        result["creation_date"]  = attrs.get("creation_date")
        result["reputation"]     = attrs.get("reputation", 0)
        # Resolutions = historical IPs this domain pointed to
        resolutions = attrs.get("last_dns_records", [])
        result["dns_records"] = [
            {"type": r.get("type"), "value": r.get("value")}
            for r in resolutions[:5]
        ]
        result["sources"].append("VirusTotal")
    else:
        result["virustotal_error"] = vt_data.get("message", vt_data["error"])

    # ── AlienVault OTX ────────────────────────────────────────
    # OTXv2 SDK is synchronous
    try:
        otx = OTXv2(OTX_KEY)
        pulses = otx.get_indicator_details_by_section(
            IndicatorTypes.DOMAIN, domain, "general"
        )
        pulse_info = pulses.get("pulse_info", {})
        result["otx_pulse_count"] = pulse_info.get("count", 0)
        result["otx_pulses"] = [
            {
                "name":        p.get("name"),
                "description": p.get("description", "")[:150],
                "tags":        p.get("tags", []),
                "created":     p.get("created")
            }
            for p in pulse_info.get("pulses", [])[:3]  # top 3 pulses
        ]
        result["sources"].append("AlienVault OTX")
    except Exception as e:
        result["otx_error"] = str(e)

    vt_malicious = result.get("vt_malicious", 0)
    otx_pulses   = result.get("otx_pulse_count", 0)
    result["verdict"] = (
        "MALICIOUS"  if (vt_malicious > 5 or otx_pulses > 3) else
        "SUSPICIOUS" if (vt_malicious > 0 or otx_pulses > 0) else
        "CLEAN"
    )

    return result


async def _lookup_hash_async(file_hash: str) -> dict:
    """Query VirusTotal for a file hash."""
    async with aiohttp.ClientSession() as session:
        vt_data = await _vt_get(session, f"files/{file_hash}")

    result = {"ioc": file_hash, "type": "hash", "sources": []}

    if "error" not in vt_data:
        attrs = vt_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result["vt_malicious"]  = stats.get("malicious", 0)
        result["vt_total"]      = sum(stats.values())
        result["file_type"]     = attrs.get("type_description")
        result["file_size"]     = attrs.get("size")
        result["first_seen"]    = attrs.get("first_submission_date")
        result["last_seen"]     = attrs.get("last_submission_date")
        result["file_names"]    = attrs.get("names", [])[:5]
        result["tags"]          = attrs.get("tags", [])
        # Extract malware family from popular threat labels
        threat_labels = attrs.get("popular_threat_classification", {})
        result["malware_family"]   = threat_labels.get("popular_threat_name", [])
        result["malware_category"] = threat_labels.get("popular_threat_category", [])
        result["sources"].append("VirusTotal")
        result["verdict"] = "MALICIOUS" if result["vt_malicious"] > 5 else (
            "SUSPICIOUS" if result["vt_malicious"] > 0 else "CLEAN"
        )
        result["confidence"] = round(result["vt_malicious"] / max(result["vt_total"], 1), 2)
    else:
        result["error"]   = vt_data.get("message", vt_data["error"])
        result["verdict"] = "UNKNOWN"

    return result


def _get_threat_actor(actor_name: str) -> dict:
    """
    Search AlienVault OTX for threat actor pulses.
    OTX doesn't have a dedicated actor endpoint, so we search
    their pulse library which is tagged by threat actor name.
    We also include a hardcoded MITRE ATT&CK reference for
    well-known APTs since OTX data varies in quality.
    """
    # Hardcoded MITRE ATT&CK data for the most common APTs
    # (OTX pulse data supplements this with live intelligence)
    MITRE_DATA = {
        "apt29": {
            "aliases": ["Cozy Bear", "The Dukes", "Midnight Blizzard", "Nobelium"],
            "origin": "Russia", "sponsor": "SVR",
            "targets": ["government", "think-tanks", "healthcare", "energy"],
            "ttps": [
                {"id": "T1566.001", "name": "Spearphishing Attachment"},
                {"id": "T1078",     "name": "Valid Accounts"},
                {"id": "T1059.001", "name": "PowerShell"},
                {"id": "T1071.001", "name": "Web Protocols C2"},
                {"id": "T1027",     "name": "Obfuscated Files"},
                {"id": "T1003",     "name": "OS Credential Dumping"},
            ],
            "campaigns": ["SolarWinds (2020)", "Microsoft breach (2024)"]
        },
        "apt28": {
            "aliases": ["Fancy Bear", "Sofacy", "Forest Blizzard", "Strontium"],
            "origin": "Russia", "sponsor": "GRU",
            "targets": ["military", "government", "aerospace", "media"],
            "ttps": [
                {"id": "T1566.002", "name": "Spearphishing Link"},
                {"id": "T1203",     "name": "Exploitation for Client Execution"},
                {"id": "T1056.001", "name": "Keylogging"},
                {"id": "T1105",     "name": "Ingress Tool Transfer"},
            ],
            "campaigns": ["DNC Hack (2016)", "French Election (2017)"]
        },
        "lazarus": {
            "aliases": ["Hidden Cobra", "Zinc", "Labyrinth Chollima"],
            "origin": "North Korea", "sponsor": "RGB",
            "targets": ["financial", "crypto", "defense", "media"],
            "ttps": [
                {"id": "T1566.001", "name": "Spearphishing Attachment"},
                {"id": "T1486",     "name": "Data Encrypted for Impact"},
                {"id": "T1041",     "name": "Exfiltration Over C2"},
                {"id": "T1204.002", "name": "Malicious File Execution"},
            ],
            "campaigns": ["WannaCry (2017)", "Bybit theft (2025)"]
        },
        "apt41": {
            "aliases": ["Double Dragon", "Winnti", "Barium"],
            "origin": "China", "sponsor": "MSS",
            "targets": ["healthcare", "telecom", "tech", "gaming"],
            "ttps": [
                {"id": "T1195.002", "name": "Supply Chain Compromise"},
                {"id": "T1190",     "name": "Exploit Public-Facing Application"},
                {"id": "T1036",     "name": "Masquerading"},
                {"id": "T1048",     "name": "Exfiltration Over Alternative Protocol"},
            ],
            "campaigns": ["ShadowPad (2017)", "Confluence exploitation (2022)"]
        }
    }

    # Normalize actor name for lookup
    key = actor_name.lower().replace(" ", "").replace("-", "").replace("_", "")
    
    # Try direct match first
    mitre_info = MITRE_DATA.get(key)
    
    # Try alias match
    if not mitre_info:
        for actor_key, data in MITRE_DATA.items():
            aliases_normalized = [
                a.lower().replace(" ", "").replace("-", "")
                for a in data["aliases"]
            ]
            if key in aliases_normalized:
                mitre_info = data
                break

    result = {
        "actor": actor_name,
        "sources": [],
        "mitre_data": mitre_info or "Not in local database"
    }

    # Supplement with live OTX pulse data
    try:
        otx = OTXv2(OTX_KEY)
        # Search OTX for pulses mentioning this actor
        search_results = otx.search_pulses(actor_name)
        pulses = search_results.get("results", [])[:5]
        result["otx_pulses"] = [
            {
                "name":        p.get("name"),
                "description": p.get("description", "")[:200],
                "tags":        p.get("tags", []),
                "ioc_count":   p.get("indicator_count", 0),
                "created":     p.get("created"),
                "author":      p.get("author_name")
            }
            for p in pulses
        ]
        result["otx_pulse_count"] = search_results.get("count", 0)
        result["sources"].append("AlienVault OTX")
    except Exception as e:
        result["otx_error"] = str(e)

    if mitre_info:
        result["sources"].append("MITRE ATT&CK (local)")

    return result


async def _check_exposure_async(software: str, version: str) -> dict:
    """
    Search NVD for CVEs affecting a software version.
    NVD's keyword search isn't version-aware, so we search by
    'software version' and filter results by CVSS score.
    """
    keyword = f"{software} {version}"
    
    async with aiohttp.ClientSession() as session:
        nvd_data = await _nvd_search(session, keyword)

    result = {
        "software": software,
        "version": version,
        "sources": ["NVD"]
    }

    if "error" in nvd_data:
        result["error"] = nvd_data.get("message", nvd_data["error"])
        return result

    vulnerabilities = nvd_data.get("vulnerabilities", [])
    
    if not vulnerabilities:
        result["cves"] = []
        result["verdict"] = "No CVEs found in NVD for this software/version combination."
        return result

    cves = []
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "Unknown")
        
        # Get CVSS score — NVD has v3.1, v3.0, and v2 scores
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = "UNKNOWN"
        
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity   = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        # Get description
        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        # Check if known exploited (CISA KEV flag in NVD)
        cisaData = cve.get("cisaExploitAdd")

        cves.append({
            "cve_id":            cve_id,
            "cvss_score":        cvss_score,
            "severity":          severity,
            "description":       desc[:300],
            "exploited_in_wild": bool(cisaData),
            "cisa_kev_date":     cisaData,
            "published":         cve.get("published", "")[:10],
            "last_modified":     cve.get("lastModified", "")[:10],
            "references":        [
                r["url"] for r in cve.get("references", [])[:3]
            ]
        })

    # Sort by CVSS score descending (most critical first)
    cves.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)
    result["cves"] = cves
    result["critical_count"] = sum(1 for c in cves if (c.get("cvss_score") or 0) >= 9.0)
    result["high_count"]     = sum(1 for c in cves if 7.0 <= (c.get("cvss_score") or 0) < 9.0)
    result["exploited_count"]= sum(1 for c in cves if c.get("exploited_in_wild"))

    return result


async def _pivot_async(ioc_type: str, value: str) -> dict:
    """
    Pivot from an IP or domain to find related infrastructure.
    - IP   → related domains (VT resolutions) + Shodan co-hosted IPs
    - Domain → historical IPs (VT passive DNS) + OTX related indicators
    """
    result = {"pivot_from": value, "type": ioc_type, "sources": []}

    async with aiohttp.ClientSession() as session:
        if ioc_type == "ip":
            vt_data = await _vt_get(session, f"ip_addresses/{value}/resolutions?limit=10")
        else:
            vt_data = await _vt_get(session, f"domains/{value}/resolutions?limit=10")

    # VirusTotal passive DNS resolutions
    if "error" not in vt_data:
        resolutions = vt_data.get("data", [])
        result["passive_dns"] = [
            {
                "value":       r.get("attributes", {}).get(
                    "host_name" if ioc_type == "ip" else "ip_address"
                ),
                "last_resolved": r.get("attributes", {}).get("date"),
                "resolver":    "VirusTotal passive DNS"
            }
            for r in resolutions
        ]
        result["sources"].append("VirusTotal")
    else:
        result["vt_error"] = vt_data.get("message", vt_data["error"])

    # For IPs — also pull Shodan co-hosted data
    if ioc_type == "ip":
        try:
            api = shodan.Shodan(SHODAN_KEY)
            host = api.host(value)
            result["shodan_hostnames"] = host.get("hostnames", [])
            result["shodan_domains"]   = host.get("domains", [])
            result["open_ports"]       = host.get("ports", [])
            result["org"]              = host.get("org")
            result["sources"].append("Shodan")
        except Exception as e:
            result["shodan_error"] = str(e)

    # For domains — also pull OTX related indicators
    if ioc_type == "domain":
        try:
            otx = OTXv2(OTX_KEY)
            indicators = otx.get_indicator_details_by_section(
                IndicatorTypes.DOMAIN, value, "url_list"
            )
            result["otx_related_urls"] = [
                u.get("url") for u in indicators.get("url_list", [])[:10]
            ]
            result["sources"].append("AlienVault OTX")
        except Exception as e:
            result["otx_error"] = str(e)

    return result


# ══════════════════════════════════════════════════════════════
# SYNC WRAPPERS
# (agent/core.py calls these — asyncio.run() bridges sync→async)
# ══════════════════════════════════════════════════════════════

def lookup_ip(ip: str) -> dict:
    return asyncio.run(_lookup_ip_async(ip))

def lookup_domain(domain: str) -> dict:
    return asyncio.run(_lookup_domain_async(domain))

def lookup_hash(hash: str) -> dict:
    return asyncio.run(_lookup_hash_async(hash))

def get_threat_actor(actor_name: str) -> dict:
    return _get_threat_actor(actor_name)

def check_exposure(software: str, version: str) -> dict:
    return asyncio.run(_check_exposure_async(software, version))

def pivot(ioc_type: str, value: str) -> dict:
    return asyncio.run(_pivot_async(ioc_type, value))


TOOL_MAP = {
    "lookup_ip":        lookup_ip,
    "lookup_domain":    lookup_domain,
    "lookup_hash":      lookup_hash,
    "get_threat_actor": get_threat_actor,
    "check_exposure":   check_exposure,
    "pivot":            pivot,
}


def execute_tool(tool_name: str, tool_input: dict) -> str:
    fn = TOOL_MAP.get(tool_name)
    if not fn:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})
    try:
        result = fn(**tool_input)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Tool execution failed: {str(e)}"})