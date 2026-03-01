# guardian-network-agent

An AI-powered network security agent using PyShark and LangGraph to detect suspicious DNS activity.

## Run

```bash
python sniffer.py
```

## Python 3.14 compatibility note

The sniffer now creates and injects an explicit asyncio event loop when constructing `pyshark.LiveCapture`.
This avoids `RuntimeError: There is no current event loop in thread 'MainThread'` on Python 3.14+ and still uses chunked `capture.sniff(timeout=...)` processing.
