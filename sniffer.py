import pyshark
import tldextract # You might need to pip install tldextract

def is_suspicious(domain):
    """
    Heuristic check: Is the domain long, gibberish, or a weird TLD?
    This saves you money by not sending 'google.com' to the AI.
    """
    ext = tldextract.extract(domain)
    # Flag if it's a suspicious Top Level Domain or very long
    suspicious_tlds = ['xyz', 'top', 'pw', 'live', 'tk']
    if ext.suffix in suspicious_tlds or len(domain) > 30:
        return True
    return False

# In your capture loop:
# if is_suspicious(query):
#     result = security_agent.invoke({"query_data": data})