import asyncio
import time

import pyshark
import tldextract



SUSPICIOUS_TLDS = {"xyz", "top", "pw", "live", "tk"}


def is_suspicious(domain: str) -> bool:
    """
    Heuristic check to reduce LLM calls for obviously benign domains.
    """
    ext = tldextract.extract(domain)
    return ext.suffix in SUSPICIOUS_TLDS or len(domain) > 30


def ensure_main_thread_event_loop() -> None:
    """
    Ensure an event loop exists for the current thread.

    PyShark expects `asyncio.get_event_loop()` to succeed during LiveCapture
    initialization. On newer Python versions (including 3.14), this raises:
    `RuntimeError: There is no current event loop in thread 'MainThread'`
    unless we create/set one explicitly.
    """
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)


def start_guardian(interface: str = "4", chunk_seconds: int = 10) -> None:
    """
    Capture DNS queries in short blocking chunks.

    Using capture.sniff(timeout=...) avoids pyshark's continuous async iterator path,
    and pre-creating the thread event loop avoids `no current event loop` errors
    on newer Python versions.
    """
    print(f"🚀 Guardian Agent is live on interface {interface} (listening in {chunk_seconds}s chunks)")

    ensure_main_thread_event_loop()
    capture = pyshark.LiveCapture(interface=interface, display_filter="udp port 53")

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

                from agent import analyze_domain

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


if __name__ == "__main__":
    start_guardian()
