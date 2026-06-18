# agent/tools.py
#
# Real API integrations with:
#   - Rate limit handling via rate_limiter.py
#   - confidence_pct (0-100) on every tool result
#   - Graceful fallback when data is missing
#   - Source attribution on every result
#   - Async parallel calls (faster)
#
# CONFIDENCE SCORING DESIGN:
#   Each tool computes confidence_pct differently based on what
#   the source data actually measures:
#
#   lookup_ip:
#     confidence = 0.5 × (abuse_score/100) + 0.5 × (vt_malicious/vt_total)
#     Both sources normalized to 0-100 then averaged
#
#   lookup_domain:
#     confidence = 0.6 × (vt_malicious/vt_total×100) + 0.4 × min(otx_pulses×10, 100)
#     VirusTotal weighted more than OTX pulse count
#
#   lookup_hash:
#     confidence = vt_malicious / vt_total × 100
#     Most precise — direct detection ratio
#
#   get_threat_actor:
#     confidence = based on OTX pulse count (more community intel = more confident)
#
#   check_exposure:
#     confidence = based on highest CVSS score + whether exploited in wild
#
#   pivot:
#     confidence = based on number of related entities found

import os
import json
import asyncio
import aiohttp
import shodan
from OTXv2 import OTXv2, IndicatorTypes
from agent.rate_limiter import limiter

# ── Load API keys ─────────────────────────────────────────────────
VT_KEY        = os.environ.get("VIRUSTOTAL_API_KEY")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY")
OTX_KEY       = os.environ.get("OTX_API_KEY")
NVD_KEY       = os.environ.get("NVD_API_KEY")
SHODAN_KEY    = os.environ.get("SHODAN_API_KEY")


# ══════════════════════════════════════════════════════════════════
# TOOL SCHEMAS
# (What Claude reads to decide which tool to call)
# ══════════════════════════════════════════════════════════════════

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
                    "description": "The IPv4 or IPv6 address to look up."
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
            "Use when an analyst provides a hash to investigate."
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
            "Profile a known threat actor or APT group using AlienVault OTX "
            "and MITRE ATT&CK data. Returns aliases, TTPs, targets, campaigns. "
            "Use for questions like 'What is APT29?' or 'Tell me about Lazarus'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "actor_name": {
                    "type": "string",
                    "description": "Name or alias of the threat actor, e.g. 'APT29'."
                }
            },
            "required": ["actor_name"]
        }
    },
    {
        "name": "check_exposure",
        "description": (
            "Check if a software version has known CVEs using the NVD database. "
            "Returns CVE IDs, CVSS scores, severity, and exploitation status. "
            "Use when analyst says 'We run X version Y — are we exposed?'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "software": {
                    "type": "string",
                    "description": "Software name, e.g. 'Confluence', 'Log4j'."
                },
                "version": {
                    "type": "string",
                    "description": "Version string, e.g. '7.13'."
                }
            },
            "required": ["software", "version"]
        }
    },
    {
        "name": "pivot",
        "description": (
            "Pivot from a known IOC to discover related entities. "
            "From an IP: finds related domains via passive DNS and Shodan. "
            "From a domain: finds historical IPs and related URLs via OTX. "
            "Use when analyst says 'pivot', 'expand', or 'find related'."
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


# ══════════════════════════════════════════════════════════════════
# CONFIDENCE SCORING HELPERS
# ══════════════════════════════════════════════════════════════════

def _ip_confidence(abuse_score: int, vt_malicious: int, 
                   vt_total: int, verdict: str) -> int:
    """
    Confidence = certainty of the verdict.
    CLEAN: based on data coverage (how many engines checked + low abuse)
    MALICIOUS/SUSPICIOUS: based on detection ratio
    """
    if verdict == "CLEAN":
        coverage     = (vt_total / 90 * 100) if vt_total > 0 else 0
        clean_signal = 100 - abuse_score
        raw = (0.6 * coverage) + (0.4 * clean_signal)
        return min(95, max(30, round(raw)))
    else:
        vt_ratio = (vt_malicious / vt_total * 100) if vt_total > 0 else 0
        raw = (0.5 * abuse_score) + (0.5 * vt_ratio)
        return min(99, max(1, round(raw)))

def _domain_confidence(vt_malicious: int, vt_total: int,
                       otx_pulses: int, verdict: str) -> int:
    """
    confidence_pct = threat confidence (consistent scale).
    CLEAN domains score LOW. MALICIOUS domains score HIGH.
    """
    vt_score  = (vt_malicious / vt_total * 100) if vt_total > 0 else 0
    otx_score = min(otx_pulses * 10, 100)
    raw = (0.6 * vt_score) + (0.4 * otx_score)
    return min(99, max(1, round(raw)))


def _hash_confidence(vt_malicious: int, vt_total: int) -> int:
    """
    Hash confidence = direct VirusTotal detection ratio.
    Most precise metric — 64/75 engines = 85%.
    """
    if vt_total == 0:
        return 0
    return min(99, round(vt_malicious / vt_total * 100))


def _actor_confidence(otx_pulse_count: int, has_mitre_data: bool) -> int:
    """
    Threat actor confidence based on community intelligence volume.
    More OTX pulses = more security researchers have documented this actor.
    MITRE local data adds a baseline floor.
    """
    if otx_pulse_count >= 100:
        base = 92
    elif otx_pulse_count >= 50:
        base = 85
    elif otx_pulse_count >= 20:
        base = 75
    elif otx_pulse_count >= 5:
        base = 62
    elif otx_pulse_count >= 1:
        base = 48
    else:
        base = 25

    # Local MITRE data adds confidence floor
    if has_mitre_data and base < 60:
        base = 60

    return min(99, base)


def _exposure_confidence(cves: list) -> int:
    """
    Exposure confidence based on highest CVSS score + exploitation status.
    CVSS 10.0 + exploited in wild = 98% confidence this is a critical risk.
    """
    if not cves:
        return 5  # very low — no CVEs found

    max_cvss = max((c.get("cvss_score") or 0) for c in cves)
    exploited_count = sum(1 for c in cves if c.get("exploited_in_wild"))

    # Base from CVSS
    if max_cvss >= 9.0:
        base = 90
    elif max_cvss >= 7.0:
        base = 75
    elif max_cvss >= 4.0:
        base = 55
    else:
        base = 30

    # Boost for known exploitation
    if exploited_count > 0:
        base = min(99, base + 8)

    return base


def _pivot_confidence(related_count: int) -> int:
    """
    Pivot confidence based on how many related entities were found.
    More passive DNS entries = more reliable infrastructure mapping.
    """
    if related_count >= 10:
        return 88
    elif related_count >= 5:
        return 75
    elif related_count >= 2:
        return 60
    elif related_count == 1:
        return 45
    else:
        return 10


# ══════════════════════════════════════════════════════════════════
# API HELPERS
# ══════════════════════════════════════════════════════════════════

async def _vt_get(session: aiohttp.ClientSession, endpoint: str) -> dict:
    """VirusTotal API v3 GET with rate limiting."""
    ok, msg = limiter.check_and_wait("virustotal")
    if not ok:
        return {"error": "rate_limited", "message": msg}

    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    headers = {"x-apikey": VT_KEY}
    try:
        async with session.get(
            url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            limiter.record_call("virustotal")
            if resp.status == 404:
                return {"error": "not_found"}
            if resp.status == 429:
                return {"error": "rate_limited", "message": "VirusTotal rate limit hit."}
            if resp.status != 200:
                return {"error": f"http_{resp.status}"}
            return await resp.json()
    except asyncio.TimeoutError:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


async def _abuseipdb_get(session: aiohttp.ClientSession, ip: str) -> dict:
    """AbuseIPDB check with rate limiting."""
    ok, msg = limiter.check_and_wait("abuseipdb")
    if not ok:
        return {"error": "rate_limited", "message": msg}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        async with session.get(
            url, headers=headers, params=params,
            timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            limiter.record_call("abuseipdb")
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
    CVE search using NIST NVD with retry logic.
    Retries 3 times with increasing delays before giving up.
    """
    ok, msg = limiter.check_and_wait("nvd")
    if not ok:
        return {"error": "rate_limited", "message": msg}

    url     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": os.environ.get("NVD_API_KEY", "")}
    params  = {"keywordSearch": keyword, "resultsPerPage": 5, "startIndex": 0}

    # Retry up to 3 times with increasing timeouts
    for attempt, timeout_secs in enumerate([10, 20, 30], start=1):
        try:
            async with session.get(
                url, headers=headers, params=params,
                timeout=aiohttp.ClientTimeout(total=timeout_secs)
            ) as resp:
                limiter.record_call("nvd")
                if resp.status == 503:
                    if attempt < 3:
                        await asyncio.sleep(5 * attempt)
                        continue
                    return {"error": "nvd_maintenance",
                            "message": "NVD is under maintenance. Try again later."}
                if resp.status == 429:
                    return {"error": "rate_limited",
                            "message": "NVD rate limit hit. Wait 30s."}
                if resp.status != 200:
                    return {"error": f"http_{resp.status}"}
                return await resp.json()

        except asyncio.TimeoutError:
            if attempt < 3:
                await asyncio.sleep(3 * attempt)
                continue
            return {"error": "timeout",
                    "message": f"NVD timed out after {attempt} attempts."}
        except Exception as e:
            return {"error": str(e)}

    return {"error": "max_retries", "message": "NVD failed after 3 attempts."}

# ══════════════════════════════════════════════════════════════════
# TOOL IMPLEMENTATIONS
# ══════════════════════════════════════════════════════════════════

async def _lookup_ip_async(ip: str) -> dict:
    """Calls AbuseIPDB + VirusTotal + Shodan in parallel."""
    async with aiohttp.ClientSession() as session:
        abuse_data, vt_data = await asyncio.gather(
            _abuseipdb_get(session, ip),
            _vt_get(session, f"ip_addresses/{ip}")
        )

    result = {"ioc": ip, "type": "ip", "sources": []}

    # ── AbuseIPDB ─────────────────────────────────────────────────
    abuse_score = 0
    if "error" not in abuse_data:
        d = abuse_data.get("data", {})
        abuse_score                        = d.get("abuseConfidenceScore", 0)
        result["abuse_score"]              = abuse_score
        result["total_reports"]            = d.get("totalReports", 0)
        result["country"]                  = d.get("countryCode", "Unknown")
        result["isp"]                      = d.get("isp", "Unknown")
        result["domain"]                   = d.get("domain", "Unknown")
        result["is_tor"]                   = d.get("isTor", False)
        result["last_reported"]            = d.get("lastReportedAt")
        reports = d.get("reports", [])[:3]
        result["recent_report_categories"] = [r.get("categories", []) for r in reports]
        result["sources"].append("AbuseIPDB")
    else:
        result["abuseipdb_error"] = abuse_data.get("message", abuse_data["error"])

    # ── VirusTotal ────────────────────────────────────────────────
    vt_malicious = 0
    vt_total     = 0
    if "error" not in vt_data:
        attrs        = vt_data.get("data", {}).get("attributes", {})
        stats        = attrs.get("last_analysis_stats", {})
        vt_malicious = stats.get("malicious", 0)
        vt_total     = sum(stats.values())
        result["vt_malicious"] = vt_malicious
        result["vt_suspicious"]= stats.get("suspicious", 0)
        result["vt_harmless"]  = stats.get("harmless", 0)
        result["vt_total"]     = vt_total
        result["network"]      = attrs.get("network", "Unknown")
        result["asn"]          = attrs.get("asn", "Unknown")
        result["as_owner"]     = attrs.get("as_owner", "Unknown")
        result["sources"].append("VirusTotal")
    else:
        result["virustotal_error"] = vt_data.get("message", vt_data["error"])

    # ── Shodan ────────────────────────────────────────────────────
    ok, msg = limiter.check_and_wait("shodan")
    if ok:
        try:
            api  = shodan.Shodan(SHODAN_KEY)
            host = api.host(ip)
            limiter.record_call("shodan")
            result["open_ports"]  = host.get("ports", [])
            result["hostnames"]   = host.get("hostnames", [])
            result["os"]          = host.get("os")
            result["tags"]        = host.get("tags", [])
            result["vulns"]       = list(host.get("vulns", {}).keys())
            result["org"]         = host.get("org")
            result["last_update"] = host.get("last_update")
            result["services"]    = [
                {
                    "port":    s.get("port"),
                    "product": s.get("product"),
                    "version": s.get("version"),
                    "banner":  s.get("data", "")[:100]
                }
                for s in host.get("data", [])[:5]
            ]
            result["sources"].append("Shodan")
        except shodan.APIError as e:
            result["shodan_error"] = str(e)
        except Exception as e:
            result["shodan_error"] = str(e)
    else:
        result["shodan_error"] = msg

    # ── Verdict + Confidence ──────────────────────────────────────
    result["verdict"] = (
        "MALICIOUS"  if (abuse_score > 50 or vt_malicious > 5) else
        "SUSPICIOUS" if (abuse_score > 20 or vt_malicious > 0) else
        "CLEAN"
    )
    result["confidence_pct"] = _ip_confidence(
        abuse_score, vt_malicious, vt_total, result["verdict"]
    )

    return result


async def _lookup_domain_async(domain: str) -> dict:
    """Query VirusTotal + OTX for a domain."""
    async with aiohttp.ClientSession() as session:
        vt_data = await _vt_get(session, f"domains/{domain}")

    result = {"ioc": domain, "type": "domain", "sources": []}

    vt_malicious = 0
    vt_total     = 0
    if "error" not in vt_data:
        attrs        = vt_data.get("data", {}).get("attributes", {})
        stats        = attrs.get("last_analysis_stats", {})
        vt_malicious = stats.get("malicious", 0)
        vt_total     = sum(stats.values())
        result["vt_malicious"]  = vt_malicious
        result["vt_suspicious"] = stats.get("suspicious", 0)
        result["vt_total"]      = vt_total
        result["categories"]    = attrs.get("categories", {})
        result["registrar"]     = attrs.get("registrar")
        result["creation_date"] = attrs.get("creation_date")
        result["reputation"]    = attrs.get("reputation", 0)
        result["dns_records"]   = [
            {"type": r.get("type"), "value": r.get("value")}
            for r in attrs.get("last_dns_records", [])[:5]
        ]
        result["sources"].append("VirusTotal")
    else:
        result["virustotal_error"] = vt_data.get("message", vt_data["error"])

    # ── AlienVault OTX ────────────────────────────────────────────
    otx_pulses = 0
    ok, msg = limiter.check_and_wait("otx")
    if ok:
        try:
            otx      = OTXv2(OTX_KEY)
            pulses   = otx.get_indicator_details_by_section(
                IndicatorTypes.DOMAIN, domain, "general"
            )
            limiter.record_call("otx")
            pulse_info = pulses.get("pulse_info", {})
            otx_pulses = pulse_info.get("count", 0)
            result["otx_pulse_count"] = otx_pulses
            result["otx_pulses"]      = [
                {
                    "name":        p.get("name"),
                    "description": p.get("description", "")[:150],
                    "tags":        p.get("tags", []),
                    "created":     p.get("created")
                }
                for p in pulse_info.get("pulses", [])[:3]
            ]
            result["sources"].append("AlienVault OTX")
        except Exception as e:
            result["otx_error"] = str(e)
    else:
        result["otx_error"] = msg

    # ── Verdict + Confidence ──────────────────────────────────────
    result["verdict"] = (
        "MALICIOUS"  if (vt_malicious > 5 or otx_pulses > 3) else
        "SUSPICIOUS" if (vt_malicious > 0 or otx_pulses > 0) else
        "CLEAN"
    )
    result["confidence_pct"] = _domain_confidence(
        vt_malicious, vt_total, otx_pulses, result["verdict"]
    )

    return result


async def _lookup_hash_async(file_hash: str) -> dict:
    """Query VirusTotal for a file hash."""
    async with aiohttp.ClientSession() as session:
        vt_data = await _vt_get(session, f"files/{file_hash}")

    result = {"ioc": file_hash, "type": "hash", "sources": []}

    vt_malicious = 0
    vt_total     = 0
    if "error" not in vt_data:
        attrs        = vt_data.get("data", {}).get("attributes", {})
        stats        = attrs.get("last_analysis_stats", {})
        vt_malicious = stats.get("malicious", 0)
        vt_total     = sum(stats.values())
        result["vt_malicious"]     = vt_malicious
        result["vt_total"]         = vt_total
        result["file_type"]        = attrs.get("type_description")
        result["file_size"]        = attrs.get("size")
        result["first_seen"]       = attrs.get("first_submission_date")
        result["last_seen"]        = attrs.get("last_submission_date")
        result["file_names"]       = attrs.get("names", [])[:5]
        result["tags"]             = attrs.get("tags", [])
        threat_labels              = attrs.get("popular_threat_classification", {})
        result["malware_family"]   = threat_labels.get("popular_threat_name", [])
        result["malware_category"] = threat_labels.get("popular_threat_category", [])
        result["sources"].append("VirusTotal")
        result["verdict"] = (
            "MALICIOUS"  if vt_malicious > 5 else
            "SUSPICIOUS" if vt_malicious > 0 else
            "CLEAN"
        )
    else:
        result["error"]   = vt_data.get("message", vt_data["error"])
        result["verdict"] = "UNKNOWN"

    result["confidence_pct"] = _hash_confidence(vt_malicious, vt_total)

    return result


def _get_threat_actor(actor_name: str) -> dict:
    """Profile a threat actor via OTX + local MITRE data."""

    MITRE_DATA = {
        "apt29": {
            "aliases":   ["Cozy Bear", "The Dukes", "Midnight Blizzard", "Nobelium"],
            "origin":    "Russia",
            "sponsor":   "SVR",
            "targets":   ["government", "think-tanks", "healthcare", "energy"],
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
            "aliases":   ["Fancy Bear", "Sofacy", "Forest Blizzard", "Strontium"],
            "origin":    "Russia",
            "sponsor":   "GRU",
            "targets":   ["military", "government", "aerospace", "media"],
            "ttps": [
                {"id": "T1566.002", "name": "Spearphishing Link"},
                {"id": "T1203",     "name": "Exploitation for Client Execution"},
                {"id": "T1056.001", "name": "Keylogging"},
                {"id": "T1105",     "name": "Ingress Tool Transfer"},
            ],
            "campaigns": ["DNC Hack (2016)", "French Election (2017)"]
        },
        "lazarus": {
            "aliases":   ["Hidden Cobra", "Zinc", "Labyrinth Chollima"],
            "origin":    "North Korea",
            "sponsor":   "RGB",
            "targets":   ["financial", "crypto", "defense", "media"],
            "ttps": [
                {"id": "T1566.001", "name": "Spearphishing Attachment"},
                {"id": "T1486",     "name": "Data Encrypted for Impact"},
                {"id": "T1041",     "name": "Exfiltration Over C2"},
                {"id": "T1204.002", "name": "Malicious File Execution"},
            ],
            "campaigns": ["WannaCry (2017)", "Bybit theft (2025)"]
        },
        "apt41": {
            "aliases":   ["Double Dragon", "Winnti", "Barium"],
            "origin":    "China",
            "sponsor":   "MSS",
            "targets":   ["healthcare", "telecom", "tech", "gaming"],
            "ttps": [
                {"id": "T1195.002", "name": "Supply Chain Compromise"},
                {"id": "T1190",     "name": "Exploit Public-Facing Application"},
                {"id": "T1036",     "name": "Masquerading"},
                {"id": "T1048",     "name": "Exfiltration Over Alternative Protocol"},
            ],
            "campaigns": ["ShadowPad (2017)", "Confluence exploitation (2022)"]
        }
    }

    key = actor_name.lower().replace(" ", "").replace("-", "").replace("_", "")

    mitre_info = MITRE_DATA.get(key)
    if not mitre_info:
        for actor_key, data in MITRE_DATA.items():
            aliases_norm = [
                a.lower().replace(" ", "").replace("-", "")
                for a in data["aliases"]
            ]
            if key in aliases_norm:
                mitre_info = data
                break

    result = {
        "actor":       actor_name,
        "sources":     [],
        "mitre_data":  mitre_info or "Not in local database"
    }

    # OTX pulse search
    otx_pulse_count = 0
    ok, msg = limiter.check_and_wait("otx")
    if ok:
        try:
            otx            = OTXv2(OTX_KEY)
            search_results = otx.search_pulses(actor_name)
            limiter.record_call("otx")
            pulses         = search_results.get("results", [])[:5]
            otx_pulse_count= search_results.get("count", 0)
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
            result["otx_pulse_count"] = otx_pulse_count
            result["sources"].append("AlienVault OTX")
        except Exception as e:
            result["otx_error"] = str(e)
    else:
        result["otx_error"] = msg

    if mitre_info:
        result["sources"].append("MITRE ATT&CK (local)")

    result["confidence_pct"] = _actor_confidence(
        otx_pulse_count, has_mitre_data=bool(mitre_info)
    )

    return result


async def _check_exposure_async(software: str, version: str) -> dict:
    """
    Check CVE exposure for a software version.
    Primary source: NIST NVD API
    Fallback source: CISA KEV (Known Exploited Vulnerabilities)
      - Always free, no API key, different infrastructure from NVD
      - Contains only actively exploited CVEs — most critical subset
      - Falls back automatically when NVD is unavailable
    """
    keyword = f"{software} {version}"
    result  = {"software": software, "version": version}

    # ── Primary: NVD ──────────────────────────────────────────────
    nvd_data = None
    async with aiohttp.ClientSession() as session:
        nvd_data = await _nvd_search(session, keyword)

    nvd_failed = "error" in nvd_data

    if not nvd_failed:
        # Parse NVD response normally
        vulnerabilities = nvd_data.get("vulnerabilities", [])
        result["sources"] = ["NVD"]

        if not vulnerabilities:
            result["cves"]           = []
            result["verdict"]        = "No CVEs found in NVD for this software/version."
            result["confidence_pct"] = 5
            return result

        cves = []
        for item in vulnerabilities:
            cve        = item.get("cve", {})
            cve_id     = cve.get("id", "Unknown")
            metrics    = cve.get("metrics", {})
            cvss_score = None
            severity   = "UNKNOWN"

            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data  = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity   = cvss_data.get("baseSeverity", "UNKNOWN")
                    break

            descriptions = cve.get("descriptions", [])
            desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available."
            )
            cisa_data = cve.get("cisaExploitAdd")
            cves.append({
                "cve_id":            cve_id,
                "cvss_score":        cvss_score,
                "severity":          severity,
                "description":       desc[:300],
                "exploited_in_wild": bool(cisa_data),
                "cisa_kev_date":     cisa_data,
                "published":         cve.get("published", "")[:10],
                "last_modified":     cve.get("lastModified", "")[:10],
                "references":        [r["url"] for r in cve.get("references", [])[:3]]
            })

        cves.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)
        result["cves"]            = cves
        result["critical_count"]  = sum(1 for c in cves if (c.get("cvss_score") or 0) >= 9.0)
        result["high_count"]      = sum(1 for c in cves if 7.0 <= (c.get("cvss_score") or 0) < 9.0)
        result["exploited_count"] = sum(1 for c in cves if c.get("exploited_in_wild"))
        result["confidence_pct"]  = _exposure_confidence(cves)
        return result

    # ── Fallback: CISA KEV ────────────────────────────────────────
    # NVD failed — query CISA KEV (no API key needed, always available)
    print(f"  [Fallback] NVD unavailable — querying CISA KEV for {software}")
    try:
        kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        async with aiohttp.ClientSession() as session:
            async with session.get(
                kev_url,
                timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status != 200:
                    raise Exception(f"CISA KEV returned {resp.status}")
                kev_data = await resp.json(content_type=None)

        all_vulns = kev_data.get("vulnerabilities", [])

        # Filter by software name (case-insensitive)
        sw_lower = software.lower()
        matching = [
            v for v in all_vulns
            if sw_lower in v.get("product", "").lower()
            or sw_lower in v.get("vendorProject", "").lower()
            or sw_lower in v.get("vulnerabilityName", "").lower()
        ]

        if not matching:
            result["cves"]           = []
            result["verdict"]        = (
                f"NVD is temporarily unavailable and no entries found "
                f"in CISA KEV for {software}. Try again later."
            )
            result["sources"]        = ["CISA KEV (NVD fallback)"]
            result["confidence_pct"] = 0
            return result

        # Convert CISA KEV format to our standard CVE format
        # CISA KEV doesn't include CVSS scores — default to HIGH (7.0)
        # since KEV only contains actively exploited vulnerabilities
        cves = []
        for v in matching[:5]:
            cves.append({
                "cve_id":            v.get("cveID", "Unknown"),
                "cvss_score":        None,   # CISA KEV doesn't provide CVSS
                "severity":          "HIGH", # All KEV entries are high priority
                "description":       v.get("shortDescription", "")[:300],
                "exploited_in_wild": True,   # All KEV entries are exploited
                "cisa_kev_date":     v.get("dateAdded"),
                "required_action":   v.get("requiredAction", ""),
                "ransomware_use":    v.get("knownRansomwareCampaignUse", "Unknown"),
                "due_date":          v.get("dueDate"),
                "published":         v.get("dateAdded", "")[:10],
                "last_modified":     v.get("dateAdded", "")[:10],
                "references":        [
                    ref.strip()
                    for ref in v.get("notes", "").split(";")
                    if ref.strip().startswith("http")
                ][:3]
            })

        result["cves"]            = cves
        result["critical_count"]  = len(cves)  # all KEV = critical
        result["exploited_count"] = len(cves)  # all KEV = exploited
        result["high_count"]      = 0
        result["sources"]         = ["CISA KEV (NVD fallback — live API unavailable)"]
        result["confidence_pct"]  = 85  # high confidence — KEV = confirmed exploited
        result["kev_note"]        = (
            "NVD was temporarily unavailable. Results from CISA KEV — "
            "contains only actively exploited vulnerabilities. "
            "CVSS scores not available from KEV; retry for full NVD data."
        )
        return result

    except Exception as e:
        result["error"]          = f"Both NVD and CISA KEV failed: {str(e)}"
        result["sources"]        = []
        result["confidence_pct"] = 0
        return result


async def _pivot_async(ioc_type: str, value: str) -> dict:
    """Pivot from an IP or domain to find related infrastructure."""
    result = {"pivot_from": value, "type": ioc_type, "sources": []}

    async with aiohttp.ClientSession() as session:
        if ioc_type == "ip":
            vt_data = await _vt_get(session, f"ip_addresses/{value}/resolutions?limit=10")
        else:
            vt_data = await _vt_get(session, f"domains/{value}/resolutions?limit=10")

    related_count = 0

    if "error" not in vt_data:
        resolutions = vt_data.get("data", [])
        related_count = len(resolutions)
        result["passive_dns"] = [
            {
                "value": r.get("attributes", {}).get(
                    "host_name" if ioc_type == "ip" else "ip_address"
                ),
                "last_resolved": r.get("attributes", {}).get("date"),
                "resolver":      "VirusTotal passive DNS"
            }
            for r in resolutions
        ]
        result["sources"].append("VirusTotal")
    else:
        result["vt_error"] = vt_data.get("message", vt_data["error"])

    # Shodan for IPs
    if ioc_type == "ip":
        ok, msg = limiter.check_and_wait("shodan")
        if ok:
            try:
                api  = shodan.Shodan(SHODAN_KEY)
                host = api.host(value)
                limiter.record_call("shodan")
                result["shodan_hostnames"] = host.get("hostnames", [])
                result["shodan_domains"]   = host.get("domains", [])
                result["open_ports"]       = host.get("ports", [])
                result["org"]              = host.get("org")
                result["sources"].append("Shodan")
            except Exception as e:
                result["shodan_error"] = str(e)
        else:
            result["shodan_error"] = msg

    # OTX for domains
    if ioc_type == "domain":
        ok, msg = limiter.check_and_wait("otx")
        if ok:
            try:
                otx        = OTXv2(OTX_KEY)
                indicators = otx.get_indicator_details_by_section(
                    IndicatorTypes.DOMAIN, value, "url_list"
                )
                limiter.record_call("otx")
                result["otx_related_urls"] = [
                    u.get("url") for u in indicators.get("url_list", [])[:10]
                ]
                result["sources"].append("AlienVault OTX")
            except Exception as e:
                result["otx_error"] = str(e)
        else:
            result["otx_error"] = msg

    result["confidence_pct"] = _pivot_confidence(related_count)

    return result


# ══════════════════════════════════════════════════════════════════
# SYNC WRAPPERS
# ══════════════════════════════════════════════════════════════════

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
