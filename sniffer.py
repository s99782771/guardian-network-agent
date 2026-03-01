import asyncio
import sys
import time

import pyshark
import tldextract

from agent import analyze_domain


SUSPICIOUS_TLDS = {"xyz", "top", "pw", "live", "tk"}


def is_suspicious(domain: str) -> bool:
    """
    Heuristic check to reduce LLM calls for obviously benign domains.
    """
    ext = tldextract.extract(domain)
    return ext.suffix in SUSPICIOUS_TLDS or len(domain) > 30


def _build_event_loop() -> asyncio.AbstractEventLoop:
    """
    Ensure pyshark gets an explicit event loop.

    Python 3.14 no longer creates a default loop implicitly in the main thread,
    so pyshark's internal `get_event_loop()` call can fail unless we provide one.
    """
    if sys.platform.startswith("win") and hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop


def start_guardian(interface: str = "4", chunk_seconds: int = 10) -> None:
    """
    Capture DNS queries in short blocking chunks.

    Uses:
    - explicit asyncio loop wiring for Python 3.14+ compatibility
    - capture.sniff(timeout=...) to avoid continuous async iterator path
    """
    print(f"🚀 Guardian Agent is live on interface {interface} (listening in {chunk_seconds}s chunks)")

    event_loop = _build_event_loop()
    capture = pyshark.LiveCapture(
        interface=interface,
        display_filter="udp port 53",
        eventloop=event_loop,
    )

    try:
        while True:
            try:
                capture.sniff(timeout=chunk_seconds)

                for packet in capture:
                    if not (hasattr(packet, "dns") and hasattr(packet.dns, "qry_name")):
                        continue

                    raw_domain = packet.dns.qry_name.rstrip(".")
                    ext = tldextract.extract(raw_domain)
                    if not ext.domain or not ext.suffix:
                        continue

                    domain = f"{ext.domain}.{ext.suffix}"
                    print(f"\n🔍 Sniffed: {domain}")

                    if not is_suspicious(domain):
                        print("⏭️ Skipped (not suspicious by local heuristic)")
                        continue

                    analysis = analyze_domain(domain)
                    print(f"🤖 AI Analysis: {analysis}")

                capture.clear()
                time.sleep(0.1)

            except KeyboardInterrupt:
                print("\n🛑 Guardian Agent stopped by user")
                break
            except Exception as exc:
                print(f"⚠️ Capture error: {exc}")
                break
    finally:
        try:
            capture.close()
        except Exception:
            pass
        event_loop.close()


if __name__ == "__main__":
    start_guardian()
