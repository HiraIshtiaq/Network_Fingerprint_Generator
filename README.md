# Network Fingerprint Generator & Website Behavior Profiler

A Flask web app that captures real network traffic to a target URL, computes a feature dictionary, builds a JSON "fingerprint", and assigns a behavior label (`Streaming` / `Social Media` / `Static Content` / `API-Heavy` / `Unknown`). The browser UI shows the fingerprint card and three Chart.js graphs (protocol pie, packet-size histogram, traffic timeline), and supports side-by-side comparison of two URLs.

---

## Table of contents

1. [Setup](#setup)
2. [Run](#run)
3. [Architecture overview](#architecture-overview)
4. [File-by-file walkthrough](#file-by-file-walkthrough)
   - [app.py](#apppy)
   - [capture.py](#capturepy)
   - [extract.py](#extractpy)
   - [fingerprint.py](#fingerprintpy)
   - [classify.py](#classifypy)
   - [templates/index.html](#templatesindexhtml)
   - [static/main.js](#staticmainjs)
   - [static/styles.css](#staticstylescss)
   - [requirements.txt](#requirementstxt)
5. [How classification works](#how-classification-works)
6. [Troubleshooting](#troubleshooting)
7. [Recent fixes](#recent-fixes)
8. [Limitations](#limitations)

---

## Setup

### macOS / Linux

```bash
cd Network_FingerPrint_Project
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### Windows

1. Install **Npcap** from <https://npcap.com> (free). During install, tick **"Install Npcap in WinPcap API-compatible Mode"**. Without Npcap, Scapy's `sniff()` cannot read packets.
2. Open **PowerShell as Administrator**:

```powershell
cd C:\path\to\Network_FingerPrint_Project
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

---

## Run

Packet capture needs raw-socket access, which means **root** on macOS/Linux and **Administrator** on Windows.

### macOS / Linux

```bash
sudo .venv/bin/python app.py
```

### Windows (Administrator PowerShell)

```powershell
.venv\Scripts\python app.py
```

Then open <http://localhost:5000>.

### Picking a specific network interface

Scapy auto-picks the default interface, but on Windows or laptops with VPNs / multiple adapters it can pick the wrong one and capture zero packets. Override it via env var:

```bash
# macOS / Linux
sudo CAPTURE_INTERFACE=en0 .venv/bin/python app.py

# Windows (PowerShell)
$env:CAPTURE_INTERFACE = "Wi-Fi"; .venv\Scripts\python app.py
```

Find the right name with `.venv/bin/python -c "from scapy.all import get_if_list; print(get_if_list())"`.

---

## Architecture overview

```
Browser (index.html + main.js + Chart.js)
        │  POST /api/analyze {url}
        ▼
Flask (app.py)
        │
        ├─► capture.py  ── BPF-filtered sniff + requests.get(url) ──► .pcap
        │
        ├─► extract.py  ── rdpcap() → feature dict
        │
        ├─► fingerprint.py ── feature dict → fingerprint JSON
        │
        └─► classify.py ── fingerprint → behavior label + confidence
                │
                ▼
        Browser renders summary card + 3 charts
```

The capture step is the only one that needs root; everything downstream is pure data processing.

---

## File-by-file walkthrough

### `app.py`

Flask glue. Owns the HTTP routes and chains capture → extract → fingerprint → classify.

| Method / route | What it does | Logic |
|---|---|---|
| `GET /` | Serves the SPA | Renders `templates/index.html`. |
| `POST /api/analyze` (`analyze`) | Single-URL fingerprint | Validates the URL, prepends `https://` if missing, resolves the hostname for inclusion in capture metadata, runs `capture_traffic` → `extract_features` → `generate_fingerprint` → `classify_behavior`, deletes the temp pcap, returns the fingerprint JSON. |
| `POST /api/compare` (`compare`) | Two-URL comparison | Same pipeline, run twice via `_process_url`, then assembles a diff and a timeline payload. Sequential capture: first URL finishes before second starts (parallel captures on one interface would interleave packets and break BPF scoping). |
| `GET /api/health` (`health_check`) | Liveness probe | Returns `{"status": "healthy"}`. Useful for verifying the server is up before triggering a capture. |
| `_process_url(url, label)` | Internal helper for compare | Captures, extracts, fingerprints, classifies, and cleans up the pcap. Returns `(fingerprint, features)` so the diff can use raw features that aren't kept on the public fingerprint. |
| `_generate_diff(fp1, fp2, f1, f2)` | Structured side-by-side diff | For each metric, returns `{site1, site2, winner, difference}`. Protocol distribution is keyed per protocol so the frontend can render a grouped bar chart. The behavior_label "winner" is `match`/`mismatch` rather than greater-than. |
| `_prepare_timeline(f1, f2)` / `_calc_timeline(times, sizes)` | Per-second byte buckets | Walks inter-arrival times, accumulates real timestamps, and bins bytes into 1-second buckets for the timeline chart. Capped at 15 buckets so a stray long inter-arrival time doesn't blow up the X axis. |

Why a sniff thread + a synchronous request in one process: `requests.get` blocks while the page loads, but `sniff()` also blocks, so one of them has to run on a background thread. We put `sniff()` on the thread and run `requests.get` on the main thread because the sniffer's blocking model is friendlier to a `stop_filter` than `requests` is to thread cancellation.

---

### `capture.py`

Captures real packets to/from the target URL into a `.pcap` file.

| Method | What it does | Logic |
|---|---|---|
| `_hostname_variants(hostname)` | Returns the hostname plus its `www.` (or non-`www.`) sibling | Most bare domains 301 to a `www.` canonical (`youtube.com` → `www.youtube.com`) and the canonical has *different* DNS records. Resolving only the entered hostname misses post-redirect IPs and the BPF filter would drop most of the traffic. |
| `_resolve_all_ips(hostname)` | Resolves every A/AAAA address for the hostname *and* its www-variant | Big sites round-robin across many edge IPs and macOS prefers IPv6 (Happy Eyeballs). `socket.getaddrinfo` walks both v4 and v6 families and we collect every unique IP across both hostname variants. |
| `_build_bpf(ips)` | Builds a Berkeley Packet Filter expression | Returns `host <ip1> or host <ip2> or ... or port 53`. Port 53 is always included because the DNS lookup happens *before* we know the resolved IP — without `port 53` in the filter the DNS query/response packets are missed and `extract.py` would report 0 DNS queries. |
| `capture_traffic(url, output_file, duration=10)` | Runs the capture | (1) Resolve all IPs. (2) Build BPF. (3) Spawn a sniffer thread that runs `sniff(filter=bpf, timeout=duration, stop_filter=...)`. If `CAPTURE_INTERFACE` env var is set, pass it as `iface=` so Scapy doesn't auto-pick the wrong adapter. (4) Wait ~1 s for libpcap to attach the filter. (5) Fire `requests.get(url)` from the main thread. (6) When the request completes, set `request_done`; the sniffer's `stop_filter` ends the capture 1.5 s later (enough to catch FIN/ACK teardown). (7) `wrpcap()` the buffered packets to disk. Catches `PermissionError` separately to give a clear "needs elevated privileges" message. Returns `target_ips` and `bpf_filter` in the result for UI diagnostics. |

Why the BPF filter is critical: without it `sniff()` captures every packet on the interface — every Slack ping, Spotify stream, OS update probe — and `extract.py` would report a fingerprint of *the whole machine's traffic*, not just the target site (this was the original bug).

Why we stop 1.5 s after the request finishes: the spec sets a 10 s default capture window, but `requests.get` on a static page finishes in <500 ms. The remaining 9.5 s would just be background noise (or zero if the BPF filter is doing its job). `stop_filter` lets us cut early without changing the spec's `duration` knob.

The `CAPTURE_INTERFACE` env var skips Scapy's auto-pick and binds sniff to a specific adapter, needed on Windows or VPN-heavy macOS setups.

---

### `extract.py`

Reads the pcap, walks every packet, and produces a feature dictionary.

| Method | What it does | Logic |
|---|---|---|
| `extract_features(pcap_file)` | Main entry point | `rdpcap()` loads the file (in-memory; NFR-3 says ≤5 MB so this is fine). Iterates packets once, accumulating byte counts, packet sizes, inter-arrival times, destination IPs, DNS queries, and a per-protocol counter. After the loop, computes summary stats (mean/min/max packet size, capture duration, bytes-per-second, packets-per-second) and the protocol distribution as percentages. |
| `_classify_packet(pkt, dest_ips, dns_queries)` | Maps one packet to one of `PROTOCOL_KEYS` | Order matters: ARP first (link layer), then IPv4 *or* IPv6 packets dispatched by transport. macOS prefers IPv6 (Happy Eyeballs) for sites with AAAA records, so the v4-only check would miss them all and bucket them as `Other` with no destination IP — that was the "every site is Static Content" bug. TCP/443 is reported as `HTTPS`, TCP/anything-else as `TCP`. UDP/53 is reported as `DNS` and we decode the query name. UDP/443 is reported as `HTTPS` because that's QUIC / HTTP-3, which Chrome and Safari opportunistically prefer. ICMP and ICMPv6 are bucketed as `ICMP`. Anything not matching falls through to `Other`. Side-effect: appends the destination IP to `dest_ips` (v4 or v6 form) and decoded DNS query names to `dns_queries`. |
| `_empty_features()` | Returns the canonical empty feature dict | Used as both the "no packets" fallback and the seed dict the main loop writes into, so every key the rest of the system might read is guaranteed to exist. |

Why we don't include source IPs in `unique_ips`: FR-3 says "list of unique destination IP addresses contacted." Counting both halves doubles the count and meaninglessly inflates the "many endpoints" signal in classification.

Why protocol counts use `Counter` and percentages are rounded to 1 decimal: stable JSON output, easier to assert against in tests, and human-readable on the UI without floating-point noise.

Why `if prev_time is not None` (not `if prev_time`): if the very first packet's timestamp ends up exactly `0.0` (rare but happens with synthetic test pcaps), `if prev_time` is falsy and we'd skip computing the first inter-arrival delta. The explicit `is not None` check is correct.

---

### `fingerprint.py`

Turns the feature dict into a stable, JSON-serializable fingerprint object.

| Method | What it does | Logic |
|---|---|---|
| `generate_fingerprint(url, features)` | Builds the public fingerprint | Copies the spec-required fields out of the feature dict, normalizes protocol percentages so they sum to exactly 100 (rounding can drift them by ~0.3), trims long arrays (`packet_sizes_sample`, `inter_arrival_times`) to 200 entries to keep the JSON payload small, and computes a SHA-256 over a deterministic subset of fields so the same site captured twice produces a comparable hash. |
| `save_fingerprint(fingerprint, output_dir)` | Writes the fingerprint to disk | Optional helper not currently called from `app.py`; useful if a student wants to keep a library of fingerprints. The filename is `<domain>_<timestamp>.json`. |

Why the hash excludes `behavior_label`, `confidence`, and timestamps: those change every run, but the underlying network behavior shouldn't. Hashing only the structural fields lets you compare "is this the same fingerprint as before?" cleanly.

---

### `classify.py`

Assigns a behavior label with a **rule-based** classifier (per FR-5: "applies a simple rule-based classifier"). Each label is one `if` block; the first matching block returns. Order is most-specific to least-specific so a streaming page can't be misread as static and an API endpoint can't be misread as social media.

| Method | What it does | Logic |
|---|---|---|
| `classify_behavior(features)` | Public entry point — runs all the rules | Returns `Unknown(0.5)` if `total_packets < 10` (no useful signal). Otherwise checks the rules below in order and returns the first match. Falls through to `Unknown(0.6)` with a "mixed pattern" reason. |
| `_result(label, confidence, characteristics)` | Builds the result dict | Just packaging. |
| `_fmt(num)` | Human-readable byte formatter | Used in the `characteristics` strings. |

See [How classification works](#how-classification-works) below for the exact rules.

---

### `templates/index.html`

Single-page UI. One mode toggle (Single / Compare), URL inputs with inline error divs, a loading spinner, a results section with the summary card + three Chart.js canvases, and a comparison results section with side-by-side cards + a diff table + two comparison charts. Loads `Chart.js` from a CDN and our `main.js` and `styles.css` from the Flask static folder.

---

### `static/main.js`

All client-side behavior. No framework — vanilla JS, one global state per chart object.

| Function | What it does |
|---|---|
| `switchMode(mode)` | Single ↔ Compare toggle. Destroys all live Chart.js instances first; otherwise the canvases hang on to old data and the next `new Chart()` warns about overlapping instances. |
| `validateURL(url, errorElementId)` | Frontend validation per FR-1. Prepends `https://` if missing, then runs `new URL()` to validate. Bad input shows an inline error and short-circuits before any fetch. |
| `analyzeSingle()` / `analyzeCompare()` | POST to `/api/analyze` or `/api/compare`. Disables the submit button while in flight to prevent double submits, shows the spinner, then calls the display functions on success. The `isAnalyzing` flag prevents mode-switching mid-capture. |
| `displaySingleResults(fp)` | Builds the summary card HTML, the **Capture Diagnostics** panel (hostname, resolved IPs, BPF filter, raw packet count — handy for spotting capture problems vs classifier problems), then calls the three chart factories. Scrolls into view at the end. |
| `createProtocolChart(fp)` | Doughnut chart of protocol_distribution percentages. |
| `createPacketSizeHistogram(fp)` | Bar chart with four buckets: 0-100, 101-500, 501-1000, 1001+ bytes (per FR-7). |
| `createTrafficTimeline(fp)` | Line chart of packets-per-second. Walks inter-arrival times and bins each packet into the cumulative-time second it landed in. |
| `displayComparisonResults(data)` | Compare mode equivalent of `displaySingleResults`: two cards, a diff table, and two overlay charts. |
| `displayCompareCards`, `displayDiffTable`, `createCompareProtocolChart`, `createCompareTimelineChart` | Build the comparison DOM and charts. |
| `formatBytes`, `escapeHtml`, `showLoading`, `showError` | Small UI helpers. `escapeHtml` matters because we render user-supplied URLs and DNS query names back into the DOM. |

---

### `static/styles.css`

Page styling: container layout, mode toggle, input groups, behavior badges (each label gets its own color so the eye can spot the classification at a glance), confidence bar, summary grid, comparison cards, charts grid, error states. Pure CSS, no preprocessor.

---

### `requirements.txt`

Three pinned-by-floor packages:

| Package | Purpose |
|---|---|
| `flask>=3.0.0` | Web framework, routes, JSON helpers. |
| `scapy>=2.5.0` | Raw packet capture (`sniff`, `rdpcap`, `wrpcap`) and protocol layer parsing (`IP`, `TCP`, `UDP`, `DNS`, `ICMP`, `ARP`). |
| `requests>=2.31.0` | The traffic generator. We deliberately use `requests.get` rather than a headless browser to keep the install footprint small (see [Limitations](#limitations)). |

---

## How classification works

`classify.py` walks five rules in priority order (most specific first). The first matching rule returns; if none match, the result is `Unknown`.

### Pre-check: not enough traffic

```text
if total_packets < 10  →  Unknown (0.50)
```

Below 10 packets there isn't enough signal to be confident about anything.

### Rule 1 — Streaming

```text
total_bytes      ≥ 200_000   AND
mean_pkt_size    ≥ 700       AND
tcp_pct          ≥ 70
                                  →  Streaming (0.85 / 0.90 / 0.95)
```

All three signals must hold together so a single large image on an otherwise-static page can't trigger streaming. `tcp_pct` here is `TCP + HTTPS` (HTTPS rides on TCP). 700 B average is the floor for "MTU-sized" — Ethernet MTU is ~1500 B and sustained streams trend that high.

The 200 KB byte floor (not 500 KB or 1 MB) is set there because `requests.get` only fetches the homepage HTML, never the actual video stream — even YouTube's homepage HTML is ~250 KB. Real video would be tens of MB but we don't trigger the JS that loads it. Confidence scales with byte volume: ≥ 1 MB → 0.95, ≥ 500 KB → 0.90, ≥ 200 KB → 0.85.

### Rule 2 — API-Heavy

```text
mean_pkt_size    ≤ 500       AND
pps              ≥ 15        AND
https_pct        ≥ 70        AND
unique_ips       1..5
                                  →  API-Heavy (0.88)
```

The "few backends" check (`unique_ips ≤ 5`) is what separates API-Heavy from Social Media — both have small packets, but Social Media fans out to many third-party hosts while an API endpoint usually has one or two backends. HTTPS-dominant (no protocol mix) is the second separator.

Mean ≤ 500 B (not ≤ 300) because real REST APIs return JSON payloads of a few hundred bytes per response. 300 B would only match microservice-style "ack" pings; 500 B captures realistic endpoints like `api.github.com/users/<x>`.

### Rule 3 — Social Media

```text
unique_ips       ≥ 8         AND
proto_mix        ≥ 2         AND
mean_pkt_size    ≤ 600
                                  →  Social Media (0.85, or 0.90 if unique_ips ≥ 15)
```

`proto_mix` counts protocols holding ≥5% of the distribution. Social pages embed widgets, trackers, and ad networks across many origins, so multiple protocols are visible (HTTPS, plain TCP, DNS, sometimes UDP/QUIC).

### Rule 4 — Static Content

```text
total_packets    ≤ 150       AND
dns_count        ≤ 3         AND
total_bytes      ≤ 250_000
                                  →  Static Content (0.85)
```

The "boring single-origin HTML page" shape: low packet count, minimal DNS activity, modest transfer. The packet ceiling sits between observed real captures of `github.com` (~130 packets, lands here) and `youtube.com` (~280 packets, caught earlier by the Streaming rule), so each lands where intuition says it should.

### Rule 5 — Default

```text
otherwise        →  Unknown (0.60) with a "Mixed pattern" reason
```

### Why this is the right priority order

- **Streaming first**: it has the most distinctive shape (heavy bytes + big packets together). Checking it later would let other rules steal it (e.g. a high-byte streaming page with 8 IPs would otherwise match Social Media).
- **API-Heavy before Social Media**: tiny packets to a few backends could otherwise match Static (low bytes) or get nothing.
- **Social Media before Static**: a dynamic page hitting many CDNs has fewer packets than people expect and could match Static if checked first.
- **Static last among positive rules**: any low-volume page falls here naturally.
- **Unknown is the catch-all**, never a positive choice.

### How this differs from the version your reviewer flagged

The bugs in the original `if/elif`:

1. `if total_bytes > 500_000 or mean_pkt_size > 800: → Streaming` — used `or`, so a single high-mean-packet-size page (think a download of one big PDF) would be tagged Streaming.
2. `if unique_ips > 8 or (pps > 15 and mean_pkt_size < 400): → Social Media` — same `or` problem; a fast API would match the second branch and be labeled Social Media.
3. The order was Streaming → Social → Static → API, but API needs to come *before* Social to avoid stealing API traffic with the IP-fanout signal.

This rewrite keeps the same shape (`if/elif/else`, same five labels) but uses `AND` of multiple signals per rule and reorders the checks so each rule fires on the right shape of traffic.

---

## Troubleshooting

The new **Capture Diagnostics** panel under each fingerprint shows hostname, resolved IPs, BPF filter, and raw packet count. Most "wrong label" complaints turn out to be capture problems — check the diagnostics first.

| Symptom | Likely cause | Fix |
|---|---|---|
| `Packet capture needs root...` | Ran without `sudo` (macOS/Linux) or non-Administrator PowerShell (Windows) | Re-run with elevated privileges. |
| macOS: `Address already in use` on port 5000 | AirPlay Receiver listens on 5000 in macOS Monterey+ | Either disable AirPlay Receiver in System Settings → General → AirDrop & Handoff, or change the `port=5000` in `app.py:236`. |
| Capture returns 0 packets / "Top Protocol: Other" / "Unique IPs: 0" | Either the wrong interface, or Scapy version that doesn't decode IPv6 | Set `CAPTURE_INTERFACE` env var. List interfaces with `from scapy.all import get_if_list; print(get_if_list())`. The IPv6 case was a real bug — fixed in `extract.py` by checking both `IP` and `IPv6` layers. |
| `Could not resolve <hostname>` | Typo in URL or no DNS | Check the URL; try `nslookup <host>` to confirm DNS works. |
| Windows: `socket.error: [Errno 10013]` | Npcap not installed or running in non-WinPcap mode | Reinstall Npcap, tick "WinPcap API-compatible Mode". |
| Behavior label is always `Static Content` despite real traffic | Probable IPv6 issue or BPF filter not catching redirect target | Look at the **Capture Diagnostics** panel: if `Resolved IPs` is small or `Packets captured` ≪ what you'd expect for the site, it's a capture problem. |
| Site you'd expect to be Streaming/Social shows `Unknown` | Capture is on the boundary of two rules | Check the actual numbers: a site lands `Unknown` when it falls into a gap (e.g., 130 packets is over Static's 150-packet ceiling but under the threshold for Streaming). Acceptable for ambiguous traffic. |

---

## Recent fixes

This list captures the bugs that were repaired during the current revision. Useful if a reviewer wants to see what changed.

- **`extract.py` — IPv6 packets were bucketed as `Other`.** `if IP in pkt` matches IPv4 only. macOS uses Happy Eyeballs and prefers IPv6 for sites with AAAA records (YouTube, Google, GitHub all qualify), so v6 packets fell into `Other` with no destination IP recorded. Result: every site read as `Static Content`. Fix: check both `IP` and `IPv6` layers; bucket UDP/443 as `HTTPS` (QUIC); bucket ICMPv6 as `ICMP`.
- **`capture.py` — BPF filter missed `www.` redirect target.** Bare-domain URLs (`youtube.com`) 301 to `www.youtube.com`, which has *different* DNS records, so the filter built from the original hostname's IPs missed most of the post-redirect traffic. Fix: `_resolve_all_ips` now resolves both bare and `www.` variants.
- **`extract.py` — `if prev_time:` dropped the first inter-arrival sample** when the first timestamp was `0.0`. Replaced with `if prev_time is not None`.
- **`extract.py` — protocol breakdown was only TCP/UDP/Other**, missing `DNS, HTTPS, ICMP, ARP` per FR-3. Now reports the full set.
- **`fingerprint.py` — `NameError: e`** in the exception fallback (`except Exception:` without `as e`).
- **`classify.py` — first-match `if/elif` with `or`-ed signals**. Single high signal could flip the label (`if total_bytes > 500_000 or mean_pkt_size > 800: → Streaming`). Now uses `and`-ed signals per rule, in the right priority order (Streaming → API → Social → Static).
- **`classify.py` — Streaming threshold of 500 KB was unreachable** because `requests.get` only fetches the homepage HTML (~250 KB even for YouTube), not the actual video stream. Lowered to 200 KB with confidence scaling.
- **`classify.py` — API mean-packet threshold of ≤ 300 B** only matched microservice acks. Real REST APIs return JSON of a few hundred bytes per response. Bumped to ≤ 500 B.
- **UI — diagnostics surface added**. Capture Diagnostics panel in the result card shows hostname, resolved IPs, BPF filter, and raw packet count, so capture problems can be distinguished from classifier problems at a glance.
- **`temp/`** had a corrupt `*.pcap` directory entry from a prior run; removed.

## Limitations

- **`requests.get` is not a browser.** It fetches the HTML response body but does not execute JavaScript, fetch sub-resources (images, CSS, scripts), or maintain cookies/sessions across page navigations. This means dynamic sites (most of the modern web) generate less traffic than a real visit would. Swap to a headless browser (`playwright`, `selenium`) inside `capture.py` if you need higher-fidelity captures.
- **Capture is local-network only.** This tool reads packets off the host machine's NIC; it cannot fingerprint a site through a NAT or capture traffic the OS has already terminated and decrypted (e.g., HTTP/3 over QUIC inside Chrome).
- **No TLS decryption.** We see the encrypted payload sizes and ports, never the contents. The fingerprint is structural, not semantic.
- **Pcap size cap.** NFR-3 says ≤5 MB. Above that, in-memory `rdpcap()` will be slow; switch to streaming with `PcapReader` if you need bigger captures.
