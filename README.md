# guardian-network-agent

A simple packet sniffer that monitors DNS traffic on a local network and flags potentially suspicious domains.

The goal of this project was to get closer to how network-level data can be captured, filtered, and turned into actionable signals.

---

## What it does

- Captures DNS traffic (UDP port 53) using PyShark
- Extracts queried domains in real time
- Applies a lightweight heuristic to filter out obviously benign traffic
- Sends potentially suspicious domains for analysis and returns a basic risk score + reason

## Prerequisites

1. Python 3.10+
2. Install TShark (required by PyShark)
   - Ubuntu/Debian: `sudo apt-get install tshark`
3. Install Python dependencies:

```bash
pip install -r requirements.txt
```

4. Set your OpenAI key:

```bash
export OPENAI_API_KEY="your_key_here"
```

or create a `.env` file:

```bash
OPENAI_API_KEY=your_key_here
```

## Run

```bash
python sniffer.py
```

The sniffer uses `capture.sniff(timeout=...)` in short chunks instead of `sniff_continuously()` to avoid asyncio event-loop conflicts seen on newer Python versions.

## Troubleshooting

- If you run on Python 3.14+ and see `RuntimeError: There is no current event loop in thread 'MainThread'`, update to the latest code in this repo; `sniffer.py` now creates/sets the event loop before starting `pyshark.LiveCapture`.
