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


def start_guardian(interface: str = "4", chunk_seconds: int = 10) -> None:
    """
    Capture DNS queries in short blocking chunks.

    Using capture.sniff(timeout=...) avoids pyshark's continuous async iterator path,
    which can trigger `RuntimeError: This event loop is already running` on newer Python.
    """
    print(f"🚀 Guardian Agent is live on interface {interface} (listening in {chunk_seconds}s chunks)")

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
