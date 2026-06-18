# eval/run_eval.py
#
# Comprehensive Eval Harness for CTI Agent
# Tests 5 dimensions:
#
# 1. GOLDEN DATASET       — ThreatFox (abuse.ch)
# 2. TOOL ABUSE           — Wrong tool / unnecessary calls / missing calls
# 3. HALLUCINATION        — Fabricated intel not grounded in tool results
# 4. CONTEXT LIMITS       — Multi-turn reference resolution across 1-5 turns
# 5. CONFIDENCE SCORING   — Is confidence_pct present, accurate, and consistent?
#
# Usage:
#   python eval/run_eval.py                → full suite
#   python eval/run_eval.py --tool-only    → tool abuse only (fast, free)
#   python eval/run_eval.py --hal-only     → hallucination only
#   python eval/run_eval.py --ctx-only     → context only
#   python eval/run_eval.py --conf-only    → confidence scoring only
#   python eval/run_eval.py --golden-only  → 

import sys
import os
import json
import time
import re
import requests
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

from agent.graph import run_agent



# ── Langfuse Eval Tracing ─────────────────────────────────────────
# Traces each eval dimension as a separate observation in Langfuse
# so you can see eval results alongside live query traces

try:
    from langfuse import Langfuse
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))
    _lf = Langfuse()
    LANGFUSE_EVAL = True
except Exception:
    _lf = None
    LANGFUSE_EVAL = False


def _trace_dimension(dimension: str, score: float, results: list, notes: str = ""):
    """Send one eval dimension result to Langfuse as a scored trace."""
    if not LANGFUSE_EVAL or not _lf:
        return
    try:
        _lf.create_event(
            name=f"eval_{dimension}",
            input={"dimension": dimension, "n_tests": len(results), "notes": notes},
            output={
                "score_pct": score,
                "passed": sum(1 for r in results if r.get("passed")),
                "failed": sum(1 for r in results if not r.get("passed"))
            }
        )
        _lf.flush()
        print(f"  Langfuse logged eval/{dimension} = {score}%")
    except Exception as e:
        print(f"  Warning: Langfuse trace failed (non-critical): {e}")



# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════

def normalize(text: str) -> str:
    return str(text).lower().strip()

def fresh_session(prefix: str, idx) -> str:
    return f"{prefix}-{idx}-{int(time.time())}"

def print_result(idx, total, passed, label=""):
    icon = "✅" if passed else "❌"
    print(f"  [{idx}/{total}] {icon} {label}")

def accuracy(correct, total):
    return round(correct / total * 100, 1) if total > 0 else 0.0


# ══════════════════════════════════════════════════════════════════
# DIMENSION 1 — GOLDEN DATASET 
# ══════════════════════════════════════════════════════════════════


def _eval_threatfox_iocs(n_samples, subtask_results):
    """
    ThreatFox IOC Ground Truth — Known malicious IPs and domains.
    Ground truth = MALICIOUS (binary, no LLM judge needed).
    Every IOC is community-verified by abuse.ch.
    Directly tests lookup_ip and lookup_domain tools.
    """
    print("\n  [IOC] ThreatFox - Known Malicious IOCs (Real Ground Truth)")

    THREATFOX_KEY = os.environ.get("THREATFOX_API_KEY", "")
    if not THREATFOX_KEY:
        print("  Warning: THREATFOX_API_KEY not set in .env - skipping")
        print("           Sign up free at https://auth.abuse.ch/")
        subtask_results.append({
            "subtask": "ThreatFox-IOC",
            "error": "THREATFOX_API_KEY not set. Sign up at https://auth.abuse.ch/"
        })
        return

    try:
        tf_resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": THREATFOX_KEY},
            json={"query": "get_iocs", "days": 3},
            timeout=15
        )
        tf_data = tf_resp.json()
        all_iocs = tf_data.get("data", [])

        if not all_iocs:
            raise Exception("No IOCs returned from ThreatFox - API key may be invalid")

        usable = [
            ioc for ioc in all_iocs
            if ioc.get("ioc_type") in ("ip:port", "domain") and ioc.get("ioc")
        ][:n_samples]

        if not usable:
            raise Exception("No ip:port or domain IOCs in ThreatFox response")

        correct = 0
        results = []

        for i, ioc in enumerate(usable):
            ioc_type = ioc.get("ioc_type", "")
            ioc_value = ioc.get("ioc", "")
            malware = ioc.get("malware", "Unknown")
            ground_truth = "MALICIOUS"

            session = fresh_session("tf_ioc", i)

            if ioc_type == "ip:port":
                ip = ioc_value.split(":")[0]
                resp = run_agent(session, f"Is {ip} malicious?")
            else:
                resp = run_agent(session, f"Is {ioc_value} malicious?")

            answer = normalize(resp["reply"])

            passed = any(
                term in answer
                for term in ["malicious", "suspicious", "threat", "harmful", "flagged"]
            )

            if passed:
                correct += 1

            results.append({
                "ioc": ioc_value,
                "ioc_type": ioc_type,
                "malware": malware,
                "ground_truth": ground_truth,
                "agent_verdict": answer[:150],
                "tools_used": [s["tool"] for s in resp.get("steps", [])],
                "confidence_pct": resp.get("confidence"),
                "passed": passed
            })
            print_result(i+1, len(usable), passed,
                f"{ioc_type}: {ioc_value[:30]} | Malware: {malware}")
            time.sleep(2)

        acc = accuracy(correct, len(results))
        print(f"  -> ThreatFox IOC Accuracy: {correct}/{len(results)} = {acc}%")
        subtask_results.append({
            "subtask": "ThreatFox-IOC",
            "accuracy": acc,
            "method": "Real ground truth - ThreatFox community-verified malicious IOCs",
            "note": "TI feed lag may cause false negatives - known limitation",
            "n": len(results),
            "results": results
        })

    except Exception as e:
        print(f"  Warning: ThreatFox IOC error: {e}")
        subtask_results.append({"subtask": "ThreatFox-IOC", "error": str(e)})


def _eval_threatfox_hashes(n_samples, subtask_results):
    """
    ThreatFox Hash Ground Truth — Known malicious file hashes.
    Directly tests lookup_hash tool with community-verified ground truth.
    Ground truth = MALICIOUS (binary, no LLM judge needed).
    """
    print("\n  [HASH] ThreatFox - Known Malicious Hashes (Real Ground Truth)")

    THREATFOX_KEY = os.environ.get("THREATFOX_API_KEY", "")
    if not THREATFOX_KEY:
        print("  Warng: THREATFOX_API_KEY not set - skipping hash eval")
        subtask_results.append({
            "subtask": "ThreatFox-Hash",
            "error": "THREATFOX_API_KEY not set"
        })
        return

    try:
        tf_resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": THREATFOX_KEY},
            json={"query": "get_iocs", "days": 3},
            timeout=15
        )
        tf_data = tf_resp.json()
        all_iocs = tf_data.get("data", [])

        hash_iocs = [
            ioc for ioc in all_iocs
            if ioc.get("ioc_type") == "md5_hash" and ioc.get("ioc")
        ][:n_samples]

        if not hash_iocs:
            raise Exception("No md5_hash IOCs in ThreatFox response")

        correct = 0
        results = []

        for i, ioc in enumerate(hash_iocs):
            ioc_value = ioc.get("ioc", "")
            malware = ioc.get("malware", "Unknown")
            session = fresh_session("tf_hash", i)

            resp = run_agent(session, f"Check hash {ioc_value}")
            answer = normalize(resp["reply"])

            passed = any(
                term in answer
                for term in ["malicious", "suspicious", "threat", "detected", "flagged"]
            )

            if passed:
                correct += 1

            results.append({
                "hash": ioc_value,
                "malware": malware,
                "ground_truth": "MALICIOUS",
                "agent_verdict": answer[:150],
                "tools_used": [s["tool"] for s in resp.get("steps", [])],
                "confidence_pct": resp.get("confidence"),
                "passed": passed
            })
            print_result(i+1, len(hash_iocs), passed,
                f"MD5: {ioc_value[:20]}... | Malware: {malware}")
            time.sleep(2)

        acc = accuracy(correct, len(results))
        print(f"  -> ThreatFox Hash Accuracy: {correct}/{len(results)} = {acc}%")
        subtask_results.append({
            "subtask": "ThreatFox-Hash",
            "accuracy": acc,
            "method": "Real ground truth - ThreatFox community-verified malicious hashes",
            "n": len(results),
            "results": results
        })

    except Exception as e:
        print(f"  Warning: ThreatFox hash error: {e}")
        subtask_results.append({"subtask": "ThreatFox-Hash", "error": str(e)})


def eval_golden_dataset(n_samples=5):
    """
    Golden Dataset evaluation using ThreatFox (abuse.ch).
    
    Ground truth: community-verified malicious IOCs — binary labels,
    no LLM judge, consistent across runs.
    
    Covers 3 of 6 agent tools directly:
      - lookup_ip     via ThreatFox ip:port entries
      - lookup_domain via ThreatFox domain entries
      - lookup_hash   via ThreatFox md5_hash entries
    
    Source: https://threatfox.abuse.ch (free, requires auth key)
    License: CC0 (public domain)
    """
    print("\n" + "="*60)
    print("DIMENSION 1: Golden Dataset (ThreatFox — abuse.ch)")
    print("   Real binary ground truth")
    print("="*60)

    subtask_results = []

    _eval_threatfox_iocs(n_samples, subtask_results)
    _eval_threatfox_hashes(n_samples, subtask_results)

    valid   = [r for r in subtask_results if "accuracy" in r]
    overall = round(sum(r["accuracy"] for r in valid) / max(len(valid), 1), 1)

    notes_parts = []
    for r in subtask_results:
        if "accuracy" in r:
            notes_parts.append(f"{r['subtask']}:{r['accuracy']}%")
        else:
            notes_parts.append(f"{r['subtask']}:ERROR")

    _trace_dimension(
        "golden_dataset", overall,
        [r for s in subtask_results if "results" in s for r in s["results"]],
        " | ".join(notes_parts)
    )

    return {
        "dimension":        "golden_dataset",
        "overall_accuracy": overall,
        "subtasks":         subtask_results
    }

# ══════════════════════════════════════════════════════════════════
# DIMENSION 2 — TOOL ABUSE
# ══════════════════════════════════════════════════════════════════

TOOL_ABUSE_CASES = [
    # Wrong tool
    {"id": "TA-01", "type": "wrong_tool",
     "query": "What TTPs does APT29 use?",
     "expected_tool": "get_threat_actor",
     "forbidden_tools": ["lookup_ip", "lookup_domain", "check_exposure"],
     "description": "Threat actor TTP question → must call get_threat_actor"},

    {"id": "TA-02", "type": "wrong_tool",
     "query": "We run Log4j 2.14.1 — are we exposed to Log4Shell?",
     "expected_tool": "check_exposure",
     "forbidden_tools": ["lookup_ip", "lookup_domain", "get_threat_actor"],
     "description": "Software exposure → must call check_exposure"},

    {"id": "TA-03", "type": "wrong_tool",
     "query": "Look up the domain malware-drop.ru",
     "expected_tool": "lookup_domain",
     "forbidden_tools": ["lookup_ip", "check_exposure"],
     "description": "Domain lookup → must call lookup_domain"},

    {"id": "TA-04", "type": "wrong_tool",
     "query": "Check hash 44d88612fea8a8f36de82e1278abb02f",
     "expected_tool": "lookup_hash",
     "forbidden_tools": ["lookup_ip", "lookup_domain", "check_exposure"],
     "description": "Hash lookup → must call lookup_hash"},

    {"id": "TA-05", "type": "wrong_tool",
     "query": "Pivot from 45.83.122.10 to related domains",
     "expected_tool": "pivot",
     "forbidden_tools": ["check_exposure", "get_threat_actor"],
     "description": "Pivot request → must call pivot not lookup_ip"},

    # Unnecessary tool (should use context from prior turn)
    {"id": "TA-06", "type": "unnecessary_tool",
     "setup_query": "Is 8.8.8.8 malicious?",
     "query": "What was the verdict for that IP?",
     "max_tools_allowed": 1,
     "description": "Re-asking verdict → must use memory, not re-call API"},

    {"id": "TA-07", "type": "unnecessary_tool",
     "setup_query": "What TTPs is APT28 known for?",
     "query": "Summarize what you just told me about that actor",
     "max_tools_allowed": 1,
     "description": "Summary of prior answer → no new tool call needed"},

    # Missing tool (must call tool before answering)
    {"id": "TA-08", "type": "missing_tool",
     "query": "Is 185.220.101.45 malicious?",
     "required_tools": ["lookup_ip"],
     "description": "IP question → MUST call lookup_ip"},

    {"id": "TA-09", "type": "missing_tool",
     "query": "We run Confluence 7.13 — are we exposed?",
     "required_tools": ["check_exposure"],
     "description": "Exposure question → MUST call check_exposure"},

    {"id": "TA-10", "type": "missing_tool",
     "query": "Tell me about Lazarus Group",
     "required_tools": ["get_threat_actor"],
     "description": "Actor question → MUST call get_threat_actor"},
]

def eval_tool_abuse() -> dict:
    print("\n" + "="*60)
    print("🔧 DIMENSION 2: Tool Abuse Detection")
    print("   Wrong tool / Unnecessary calls / Missing calls")
    print("="*60)

    results      = []
    passed_count = 0

    for i, case in enumerate(TOOL_ABUSE_CASES):
        ctype   = case["type"]
        session = fresh_session("toolabuse", case["id"])

        if ctype == "unnecessary_tool":
            try:
                run_agent(session, case["setup_query"])
                time.sleep(2)
                resp = run_agent(session, case["query"])
            except Exception as e:
                print(f"  ⚠️  Timeout on {case['id']} — skipping")
                results.append({
                    "id": case["id"], "type": ctype,
                    "description": case["description"],
                    "tools_used": [], "passed": False,
                    "detail": f"timeout: {e}"
                })
                continue
        else:
            resp = run_agent(session, case["query"])

        tools_used = [s["tool"] for s in resp.get("steps", [])]

        if ctype == "wrong_tool":
            passed = (case["expected_tool"] in tools_used and
                      not any(t in tools_used for t in case["forbidden_tools"]))
            detail = f"called={tools_used}, expected={case['expected_tool']}"
        elif ctype == "unnecessary_tool":
            passed = len(tools_used) <= case["max_tools_allowed"]
            detail = f"tool_calls={len(tools_used)}, max_allowed={case['max_tools_allowed']}"
        elif ctype == "missing_tool":
            passed = all(t in tools_used for t in case["required_tools"])
            detail = f"called={tools_used}, required={case['required_tools']}"
        else:
            passed = False
            detail = "unknown case type"

        if passed:
            passed_count += 1

        results.append({
            "id": case["id"], "type": ctype,
            "description": case["description"],
            "tools_used": tools_used,
            "passed": passed, "detail": detail
        })
        print_result(i+1, len(TOOL_ABUSE_CASES), passed,
                     f"[{ctype.upper()}] {case['description'][:50]}")
        time.sleep(1.5)

    acc = accuracy(passed_count, len(TOOL_ABUSE_CASES))
    print(f"\n  → Tool Abuse Score: {passed_count}/{len(TOOL_ABUSE_CASES)} = {acc}%")
    _trace_dimension("tool_abuse", acc, results,
        f"Wrong:{sum(1 for r in results if r['type']=='wrong_tool' and r['passed'])}/5 "
        f"Unnecessary:{sum(1 for r in results if r['type']=='unnecessary_tool' and r['passed'])}/2 "
        f"Missing:{sum(1 for r in results if r['type']=='missing_tool' and r['passed'])}/3"
    )
    return {"dimension": "tool_abuse", "accuracy": acc, "results": results}


# ══════════════════════════════════════════════════════════════════
# DIMENSION 3 — HALLUCINATION DETECTION
# ══════════════════════════════════════════════════════════════════

HALLUCINATION_CASES = [
    {"id": "HAL-01", "type": "fabricated_ioc",
        "query": "Is 192.0.2.1 malicious? Give me its exact abuse score and open ports.",
        "description": "RFC 5737 documentation IP — should return not found or no data",
        "expect_clean": True,
        "fabrication_signals": [
            r"open ports?.{0,30}\d{2,5}",   # invented port numbers
            r"running.{0,30}(ssh|http|ftp)", # invented services
            r"malware.{0,30}family",          # invented malware
        ]},

    {"id": "HAL-02", "type": "fabricated_ioc",
     "query": "What is the VirusTotal detection ratio for domain unknown-xyz-test-999.io?",
     "description": "Unknown domain — should return not found, not invent detections",
     "expect_clean": True,
     "fabrication_signals": [r"\d{2,3}/\d{2,3}", r"flagged by \d+"]},

    {"id": "HAL-03", "type": "invented_actor",
     "query": "Tell me about threat actor BlueKitsune — what are their TTPs?",
     "description": "Fictitious actor — must say unknown, not invent TTPs",
     "expect_clean": True,
     "fabrication_signals": [r"T1\d{3}", r"known for targeting", r"their primary tactic"]},

    {"id": "HAL-04", "type": "scope_creep",
     "query": "Is CVE-2099-99999 critical? What systems does it affect?",
     "description": "Future/nonexistent CVE — must say not found",
     "expect_clean": True,
     "fabrication_signals": [r"cvss.{0,20}[89]\.\d", r"affects.{0,50}(windows|linux)",
                              r"remote code execution"]},

    {"id": "HAL-05", "type": "scope_creep",
     "query": "What is the current stock price of CrowdStrike?",
     "description": "Out-of-scope financial — must decline",
     "expect_clean": True,
     "fabrication_signals": [r"\$\d+\.\d{2}", r"trading at", r"per share"]},

    # Positive controls — these SHOULD have specific data
    {"id": "HAL-06", "type": "positive_control",
        "query": "What TTPs does APT29 use?",
        "description": "Well-known actor — SHOULD cite specific MITRE TTP IDs",
        "expect_clean": False,
        "must_contain": ["T1", "mitre", "source"]},
]

JUDGE_PROMPT = """You are evaluating whether an AI threat intelligence agent hallucinated.

Agent query: {query}
Agent response: {response}
Tools actually called: {tools}

Did the agent state specific factual claims (numbers, IDs, scores, names) 
that could NOT have come from the tool calls listed?

Reply with exactly one word: HALLUCINATED or GROUNDED
- HALLUCINATED = agent invented specific facts not in tool results
- GROUNDED = agent used tool data correctly OR appropriately said not found/unknown"""

def eval_hallucination(use_llm_judge: bool = True) -> dict:
    print("\n" + "="*60)
    print("🧠 DIMENSION 3: Hallucination Detection")
    print("   Fabricated IOC data / Invented actors / Scope creep")
    print("="*60)

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
        judge_ok = True
    except Exception:
        client   = None
        judge_ok = False
        print("  ℹ️  LLM judge unavailable — using regex only")

    results      = []
    passed_count = 0

    for i, case in enumerate(HALLUCINATION_CASES):
        session = fresh_session("hal", case["id"])
        resp    = run_agent(session, case["query"])
        answer  = resp["reply"]
        tools   = [s["tool"] for s in resp.get("steps", [])]

        # Regex check
        if case["expect_clean"]:
            regex_fabricated = any(
                re.search(p, answer, re.IGNORECASE)
                for p in case.get("fabrication_signals", [])
            )
            regex_passed = not regex_fabricated
        else:
            regex_passed = all(
                t.lower() in answer.lower()
                for t in case.get("must_contain", [])
            )

        # LLM-as-Judge
        llm_verdict = None
        llm_passed  = regex_passed
        if judge_ok and use_llm_judge and client:
            try:
                jr = client.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=10,
                    messages=[{"role": "user", "content": JUDGE_PROMPT.format(
                        query=case["query"],
                        response=answer[:800],
                        tools=tools
                    )}]
                )
                llm_verdict = jr.content[0].text.strip().upper()
                if case["expect_clean"]:
                    llm_passed = (llm_verdict == "GROUNDED")
                else:
                    llm_passed = True
            except Exception as e:
                llm_verdict = f"ERROR: {e}"

        passed = regex_passed and llm_passed
        if passed:
            passed_count += 1

        results.append({
            "id": case["id"], "type": case["type"],
            "description": case["description"],
            "tools_used": tools,
            "regex_passed": regex_passed,
            "llm_judge": llm_verdict,
            "passed": passed,
            "answer_snippet": answer[:200]
        })
        print_result(i+1, len(HALLUCINATION_CASES), passed,
                     f"[{case['type'].upper()}] {case['description'][:50]}")
        time.sleep(1.5)

    acc = accuracy(passed_count, len(HALLUCINATION_CASES))
    print(f"\n  → Hallucination Score: {passed_count}/{len(HALLUCINATION_CASES)} = {acc}%")
    _trace_dimension("hallucination", acc, results,
        f"Regex+LLM-Judge dual method, {len(results)} test cases"
    )
    return {"dimension": "hallucination", "accuracy": acc, "results": results}


# ══════════════════════════════════════════════════════════════════
# DIMENSION 4 — CONTEXT WINDOW LIMITS
# ══════════════════════════════════════════════════════════════════

CONTEXT_CASES = [
    {"id": "CTX-01", "type": "shallow_reference",
     "description": "Pronoun 'its' resolved after 1 turn",
     "turns": [
         {"query": "Is 45.83.122.10 malicious?",             "is_setup": True},
         {"query": "What is its ASN?",
          "expected": ["asn", "as4", "as5", "as6", "hostkey"], "is_setup": False},
     ]},

    {"id": "CTX-02", "type": "deep_reference",
     "description": "Reference survives a noise turn",
     "turns": [
         {"query": "Is 45.83.122.10 malicious?",             "is_setup": True},
         {"query": "Tell me a fun fact about cybersecurity",  "is_setup": True},
         {"query": "What country is that IP from?",
          "expected": ["netherlands", "germany", "russia", "us", "country"], "is_setup": False},
     ]},

    {"id": "CTX-03", "type": "entity_confusion",
     "description": "Distinguishes APT28 vs APT29 after both discussed",
     "turns": [
         {"query": "Tell me about APT29",                     "is_setup": True},
         {"query": "Now tell me about APT28",                 "is_setup": True},
         {"query": "Which of the two is linked to Russia's GRU?",
          "expected": ["apt28", "fancy bear", "gru", "sofacy"], "is_setup": False},
     ]},

    {"id": "CTX-04", "type": "pivot_reference",
     "description": "'That IP' resolved correctly for pivot",
     "turns": [
         {"query": "Is 45.83.122.10 malicious?",             "is_setup": True},
         {"query": "Pivot from that IP to related domains",
          "expected": ["domain", "passive dns", "pivot", "resolution"], "is_setup": False},
     ]},

    {"id": "CTX-05", "type": "long_context",
     "description": "Recalls first IOC after 4 unrelated turns",
     "turns": [
         {"query": "Is 45.83.122.10 malicious?",             "is_setup": True},
         {"query": "What TTPs does APT29 use?",              "is_setup": True},
         {"query": "We run Confluence 7.13 — are we exposed?","is_setup": True},
         {"query": "Check hash 44d88612fea8a8f36de82e1278abb02f", "is_setup": True},
         {"query": "What was the verdict for the first IP we looked at?",
          "expected": ["45.83.122.10", "malicious", "suspicious", "clean"], "is_setup": False},
     ]},

    {"id": "CTX-06", "type": "reference_collision",
     "description": "Distinguishes IP verdict from domain verdict",
     "turns": [
         {"query": "Is 45.83.122.10 malicious?",             "is_setup": True},
         {"query": "Check domain malware-drop.ru",           "is_setup": True},
         {"query": "What was the verdict for the IP specifically?",
          "expected": ["45.83.122.10", "suspicious", "clean", "malicious"], "is_setup": False},
     ]},
]

def eval_context_limits() -> dict:
    print("\n" + "="*60)
    print("🔄 DIMENSION 4: Context Window & Multi-Turn Limits")
    print("   Reference resolution / Entity confusion / Long context")
    print("="*60)

    results      = []
    passed_count = 0

    for i, case in enumerate(CONTEXT_CASES):
        session   = fresh_session("ctx", case["id"])
        final_resp = None

        for turn in case["turns"]:
            resp = run_agent(session, turn["query"])
            if not turn["is_setup"]:
                final_resp = resp
            time.sleep(1.5)

        if final_resp is None:
            results.append({"id": case["id"], "error": "no eval turn"})
            continue

        answer   = normalize(final_resp["reply"])
        eval_turn = next(t for t in case["turns"] if not t["is_setup"])
        expected  = eval_turn.get("expected", [])
        passed    = any(e in answer for e in expected)

        if passed:
            passed_count += 1

        results.append({
            "id": case["id"], "type": case["type"],
            "description": case["description"],
            "n_turns": len(case["turns"]),
            "expected": expected,
            "answer_snippet": answer[:200],
            "passed": passed
        })
        print_result(i+1, len(CONTEXT_CASES), passed,
                     f"[{case['type'].upper()}] {case['description'][:50]}")

    acc = accuracy(passed_count, len(CONTEXT_CASES))
    print(f"\n  → Context Score: {passed_count}/{len(CONTEXT_CASES)} = {acc}%")
    _trace_dimension("context_limits", acc, results,
        f"Tested {len(results)} scenarios from 1-5 turns deep"
    )
    return {"dimension": "context_limits", "accuracy": acc, "results": results}


# ══════════════════════════════════════════════════════════════════
# DIMENSION 5 — CONFIDENCE SCORING VALIDATION
# ══════════════════════════════════════════════════════════════════
#
# Tests 3 properties of confidence scores:
#   A. PRESENCE    — Is confidence_pct always returned by tools?
#   B. ACCURACY    — Do scores correlate with actual threat severity?
#   C. CONSISTENCY — Does a clearly malicious IOC score higher than a clean one?

CONFIDENCE_CASES = [
    # High confidence expected (well-known malicious / heavily documented)
    {"id": "CONF-01", "query": "We run Confluence 7.13 — are we exposed?",
     "expected_min_pct": 80,
     "reason": "Multiple critical CVEs + exploited in wild → must be ≥80%",
     "category": "high_expected"},

    {"id": "CONF-02", "query": "What TTPs does APT29 use?",
     "expected_min_pct": 70,
     "reason": "Well-documented actor with 100+ OTX pulses → must be ≥70%",
     "category": "high_expected"},

    {"id": "CONF-03", "query": "Check hash 44d88612fea8a8f36de82e1278abb02f",
     "expected_min_pct": 60,
     "reason": "EICAR test file — detected by most engines → must be ≥60%",
     "category": "high_expected"},

    # Low confidence expected (unknown / clean)
    {"id": "CONF-04", "query": "Is 8.8.8.8 malicious?",
     "expected_max_pct": 20,
     "reason": "Google DNS — clean IP → malicious confidence must be ≤20%",
     "category": "low_expected"},

    # Presence check — confidence must appear in answer text
    {"id": "CONF-05", "query": "Is 45.83.122.10 malicious?",
     "must_contain_pct_in_reply": True,
     "reason": "Agent must display confidence % in its answer",
     "category": "presence"},

    {"id": "CONF-06", "query": "We run Log4j 2.14 — are we exposed?",
     "must_contain_pct_in_reply": True,
     "reason": "Exposure answers must include confidence %",
     "category": "presence"},

    # Consistency — high threat must score higher than low threat
    {"id": "CONF-07",
     "query_high": "We run Confluence 7.13 — are we exposed?",
     "query_low":  "We run Confluence 8.0 — are we exposed?",
     "reason": "7.13 has critical CVEs, 8.0 is patched → 7.13 must score higher",
     "category": "consistency"},
]

def eval_confidence_scoring() -> dict:
    """
    Validates that confidence_pct is:
    1. Present in tool results and displayed in answers
    2. Numerically correct (high for malicious, low for clean)
    3. Consistent (more dangerous = higher score)
    """
    print("\n" + "="*60)
    print("📊 DIMENSION 5: Confidence Score Validation")
    print("   Presence / Accuracy / Consistency")
    print("="*60)

    results      = []
    passed_count = 0
    total        = 0

    for case in CONFIDENCE_CASES:
        cid      = case["id"]
        category = case["category"]

        # ── Consistency test (two queries) ────────────────────────
        if category == "consistency":
            total += 1
            session_h = fresh_session("conf_h", cid)
            session_l = fresh_session("conf_l", cid)

            resp_h = run_agent(session_h, case["query_high"])
            time.sleep(1.5)
            resp_l = run_agent(session_l, case["query_low"])

            conf_h = resp_h.get("confidence") or 0
            conf_l = resp_l.get("confidence") or 0
            passed = conf_h > conf_l

            if passed:
                passed_count += 1

            results.append({
                "id": cid, "category": category,
                "reason": case["reason"],
                "high_query_confidence": conf_h,
                "low_query_confidence":  conf_l,
                "passed": passed,
                "detail": f"high={conf_h}% vs low={conf_l}% (high must be greater)"
            })
            print_result(
                CONFIDENCE_CASES.index(case)+1, len(CONFIDENCE_CASES), passed,
                f"[CONSISTENCY] {case['reason'][:55]}"
            )
            time.sleep(1.5)
            continue

        # ── Single query tests ────────────────────────────────────
        total += 1
        session = fresh_session("conf", cid)
        resp    = run_agent(session, case["query"])
        conf    = resp.get("confidence")
        answer  = resp["reply"]

        if category == "high_expected":
            min_pct = case["expected_min_pct"]
            passed  = conf is not None and conf >= min_pct
            detail  = f"got {conf}%, need ≥{min_pct}%"

        elif category == "low_expected":
            max_pct = case["expected_max_pct"]
            # For clean IPs: if conf is None (no malicious signal) that's fine too
            passed  = conf is None or conf <= max_pct
            detail  = f"got {conf}%, need ≤{max_pct}% (or None for clean)"

        elif category == "presence":
            # Check that a percentage appears in the reply text
            pct_in_reply = bool(re.search(r'\d{1,3}%', answer))
            passed       = pct_in_reply
            detail       = f"percentage in reply: {pct_in_reply}"

        else:
            passed = False
            detail = "unknown category"

        if passed:
            passed_count += 1

        results.append({
            "id": cid, "category": category,
            "confidence_pct": conf,
            "reason": case["reason"],
            "passed": passed,
            "detail": detail,
            "answer_snippet": answer[:150]
        })
        print_result(
            CONFIDENCE_CASES.index(case)+1, len(CONFIDENCE_CASES), passed,
            f"[{category.upper()}] {case['reason'][:55]}"
        )
        time.sleep(1.5)

    acc = accuracy(passed_count, total)
    print(f"\n  → Confidence Score: {passed_count}/{total} = {acc}%")
    _trace_dimension("confidence_scoring", acc, results,
        f"Presence/Accuracy/Consistency checks, {total} test cases"
    )
    return {"dimension": "confidence_scoring", "accuracy": acc, "results": results}


# ══════════════════════════════════════════════════════════════════
# MAIN RUNNER
# ══════════════════════════════════════════════════════════════════

def run_full_eval(golden_samples: int = 5,
                  run_golden:     bool = True,
                  run_tool_abuse: bool = True,
                  run_hallucination: bool = True,
                  run_context:    bool = True,
                  run_confidence: bool = True) -> dict:

    print("\n" + "█"*60)
    print("  CTI AGENT — COMPREHENSIVE EVALUATION HARNESS")
    print(f"  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  Dimensions: Golden Dataset | Tool Abuse | Hallucination")
    print("              Context Limits | Confidence Scoring")
    print("█"*60)

    all_results = {}

    if run_golden:
        all_results["golden_dataset"]   = eval_golden_dataset(golden_samples)
        time.sleep(2)
    if run_tool_abuse:
        all_results["tool_abuse"]       = eval_tool_abuse()
        time.sleep(2)
    if run_hallucination:
        all_results["hallucination"]    = eval_hallucination()
        time.sleep(2)
    if run_context:
        all_results["context_limits"]   = eval_context_limits()
        time.sleep(2)
    if run_confidence:
        all_results["confidence_scoring"] = eval_confidence_scoring()

    # ── Summary ───────────────────────────────────────────────────
    print("\n" + "█"*60)
    print("  FINAL EVALUATION SUMMARY")
    print("█"*60)

    scores = {}
    for dim, res in all_results.items():
        score = res.get("overall_accuracy") or res.get("accuracy")
        if score is not None:
            scores[dim] = score
            bar = "█" * int(score / 5) + "░" * (20 - int(score / 5))
            print(f"  {dim:<25} [{bar}] {score}%")

    if scores:
        overall = round(sum(scores.values()) / len(scores), 1)
        print(f"\n  {'OVERALL':<25} {overall}%")
    print("█"*60)

    # Save timestamped results
    os.makedirs(os.path.join(os.path.dirname(__file__)), exist_ok=True)
    out_path = os.path.join(
        os.path.dirname(__file__),
        f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    with open(out_path, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "scores":    scores,
            "overall":   overall if scores else None,
            "details":   all_results
        }, f, indent=2)
    print(f"\n  ✅ Results saved to {out_path}")
    return all_results


# ── Entry Point ───────────────────────────────────────────────────
if __name__ == "__main__":
    args = sys.argv[1:]
    if   "--tool-only"   in args: eval_tool_abuse()
    elif "--hal-only"    in args: eval_hallucination()
    elif "--ctx-only"    in args: eval_context_limits()
    elif "--conf-only"   in args: eval_confidence_scoring()
    elif "--golden-only" in args: eval_golden_dataset(n_samples=5)
    else: run_full_eval(golden_samples=5)
