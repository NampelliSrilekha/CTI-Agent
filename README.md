# CTI-Agent

A **Conversational Threat Intelligence (CTI) analyst** for Security Operations Centers. Ask natural-language questions about IPs, domains, file hashes, threat actors, and software vulnerabilities — the agent selects the right tools, queries live intel sources, and returns structured verdicts with source attribution.

Built with **LangGraph** (ReAct agent loop), **Claude Sonnet**, and **FastAPI**, with a browser UI and a real-time tool-call trace panel.

---

## Features

- **Multi-turn investigations** — conversation memory per session; follow-ups like *"pivot from that IP"* resolve context from prior messages
- **Six CTI tools** — IP/domain/hash lookup, threat actor profiling, CVE exposure checks, and infrastructure pivoting
- **Live API integrations** — VirusTotal, AbuseIPDB, AlienVault OTX, CISA KEV/NVD, and Shodan
- **Agent observability** — every tool call (name + inputs) is returned to the UI trace panel
- **Prompt injection defenses** — input scanning and tool-output sanitization before data reaches the LLM
- **Structured analyst output** — verdict-first responses with confidence levels and cited sources
- **Langfuse observability** — full distributed trace of every tool call, token usage, and cost per query visible at cloud.langfuse.com
- **Eval/test harness** — tested against ThreatFox (abuse.ch) ground truth IOCs with 88%+ accuracy across 5 evaluation dimensions

---

## Architecture

```
┌─────────────┐     POST /chat      ┌──────────────┐
│  ui/        │ ──────────────────► │  app.py      │
│  index.html │ ◄────────────────── │  (FastAPI)   │
└─────────────┘   reply + steps     └──────┬───────┘
                                           │
                                           ▼
                                  ┌─────────────────┐
                                  │  agent/graph.py │
                                  │  LangGraph ReAct│
                                  │  + MemorySaver  │
                                  └────────┬────────┘
                                           │
                         ┌─────────────────┼─────────────────┐
                         ▼                 ▼                 ▼
                  lookup_ip         get_threat_actor      pivot
                  lookup_domain     check_exposure
                  lookup_hash
                         │
                         ▼
                  agent/tools.py  ──►  External CTI APIs
```

The agent runs a standard **ReAct loop**: the LLM decides which tool to call → the tool fetches data → results are fed back → the LLM synthesizes a final answer. LangGraph's `MemorySaver` checkpoints state by `session_id`, enabling multi-turn context.

---

## Project Structure

```
CTI-Agent/
├── app.py                  # FastAPI server — /chat endpoint + static UI
├── agent/
│   ├── graph.py            # LangGraph agent, system prompt, tool wrappers
│   ├── tools.py            # Async CTI API integrations
│   └── injection_guard.py  # Prompt injection detection & output sanitization
├── ui/
│   └── index.html          # Chat UI + agent trace panel
├── eval/
│   └── run_eval.py         # Eval/test harness
├── requirements.txt
└── .env                    # API keys (not committed)
```

---

## Tools

| Tool | Description | Data Sources |
|------|-------------|--------------|
| `lookup_ip` | IP reputation, abuse score, open ports | AbuseIPDB, VirusTotal, Shodan |
| `lookup_domain` | Domain reputation and threat pulses | VirusTotal, AlienVault OTX |
| `lookup_hash` | File hash malware detection | VirusTotal |
| `get_threat_actor` | APT profile — aliases, TTPs, targets | OTX, MITRE ATT&CK (local reference) |
| `check_exposure` | CVE lookup for a software + version | NVD (CISA KEV fallback when NVD unavailable) |
| `pivot` | Related domains/IPs from an IOC | Shodan, AlienVault OTX |

---

## Prerequisites

- Python 3.11+ (tested with 3.14)
- API keys for the services you want to use (see below)

---

## Setup

**1. Clone and create a virtual environment**

```bash
cd CTI-Agent
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Configure environment variables**

Create a `.env` file in the project root:

```env
ANTHROPIC_API_KEY=your_anthropic_key
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
OTX_API_KEY=your_otx_key
NVD_API_KEY=your_nvd_key
SHODAN_API_KEY=your_shodan_key
```

| Variable | Required | Purpose |
|----------|----------|---------|
| `ANTHROPIC_API_KEY` | Yes | Powers the LLM (Claude Sonnet) |
| `VIRUSTOTAL_API_KEY` | Recommended | IP, domain, and hash lookups |
| `ABUSEIPDB_API_KEY` | Recommended | IP abuse scores |
| `OTX_API_KEY` | Recommended | Threat pulses, actor intel, pivots |
| `NVD_API_KEY` | Optional | CVE / exposure checks (works without, but rate-limited) |
| `SHODAN_API_KEY` | Optional | Open ports, hostnames, pivot data |
| `LANGFUSE_PUBLIC_KEY` | Optional | Observability tracing via Langfuse |
| `LANGFUSE_SECRET_KEY` | Optional | Observability tracing via Langfuse |
| `LANGFUSE_HOST` | Optional | Langfuse host (default: https://us.cloud.langfuse.com) |
| `THREATFOX_API_KEY` | Optional | ThreatFox IOC ground truth for eval harness |

**4. Run the server**

```bash
python app.py
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

---

## API

### `POST /chat`

```json
{
  "session_id": "abc123",
  "message": "Is 45.83.122.10 malicious?"
}
```

**Response:**

```json
{
  "reply": "**MALICIOUS**\n\n- Abuse score: 87/100\n...",
  "steps": [
    { "tool": "lookup_ip", "input": { "ip": "45.83.122.10" } }
  ]
}
```

- `session_id` — reuse the same ID across requests to maintain conversation history
- `steps` — tool calls made during this turn (shown in the UI trace panel)

---

## Example Queries

- *Is 45.83.122.10 malicious?*
- *What TTPs is APT29 known for?*
- *We run Confluence 7.13 — are we exposed?*
- *Check hash 44d88612fea8a8f36de82e1278abb02f*
- *Pivot from that IP to related domains* (follow-up — uses session memory)

---

## Security

- **Direct injection blocking** — user input is scanned for patterns like "ignore instructions" before reaching the agent
- **Indirect injection defense** — tool outputs are wrapped and role-like prefixes are redacted so external data cannot hijack the conversation
- **Tool-first policy** — the system prompt instructs the agent to always call tools and never fabricate intel
- **Deterministic LLM** — `temperature=0` for consistent, reproducible analysis

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Agent orchestration | LangGraph 1.x (`create_react_agent`) |
| LLM | Claude Sonnet (via `langchain-anthropic`) |
| Tool framework | LangChain `@tool` decorators |
| Memory | LangGraph `MemorySaver` (in-process) |
| API server | FastAPI + Uvicorn |
| HTTP client | aiohttp (async parallel API calls) |
| Frontend | Vanilla HTML/CSS/JS |


