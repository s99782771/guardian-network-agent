# guardian-network-agent

An AI-powered network security agent using PyShark and LangGraph to detect suspicious DNS activity.

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
