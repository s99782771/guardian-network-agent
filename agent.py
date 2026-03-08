import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI


load_dotenv()


def analyze_domain(domain: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Add it to your environment or a .env file before running Guardian."
        )

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, api_key=api_key)
    prompt = (
        "As a security analyst, analyze this domain for malware/phishing risks: "
        f"{domain}. Respond with a risk score 1-10 and a brief reason."
    )
    response = llm.invoke(prompt)
    return response.content


if __name__ == "__main__":
    test_domain = "google.com"
    print(f"Analyzing {test_domain}...")
    print(analyze_domain(test_domain))
