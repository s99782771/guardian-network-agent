import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

# Load your new key from .env
load_dotenv()

def analyze_domain(domain):
    # Initialize the LLM (using 4o-mini for speed and low cost)
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    
    prompt = f"As a security analyst, analyze this domain for malware/phishing risks: {domain}. Respond with a risk score 1-10 and a brief reason."
    
    response = llm.invoke(prompt)
    return response.content

if __name__ == "__main__":
    # Test it out!
    test_domain = "google.com"
    print(f"Analyzing {test_domain}...")
    print(analyze_domain(test_domain))