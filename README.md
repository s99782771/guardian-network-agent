# guardian-network-agent

An AI-powered network security agent using PyShark and LangGraph to detect suspicious DNS activity.

## Run

```bash
python sniffer.py
```

The sniffer uses `capture.sniff(timeout=...)` in short chunks instead of `sniff_continuously()` to avoid asyncio event-loop conflicts seen on newer Python versions.
