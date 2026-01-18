import os
import json
from datetime import datetime, timezone
import boto3
import uuid

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langchain.tools import tool

import requests

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["TABLE_NAME"])

@tool(description="Reverses the input text")
def reverse_text(text: str) -> str:
    return text[::-1]


@tool(description="Returns current UTC time")
def utc_time(_: str) -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@tool(description="Check an IP address reputation using VirusTotal")
def virustotal_ip_lookup(ip: str) -> str:
    """
    Queries VirusTotal for IP reputation and returns a summary.
    """
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return "VirusTotal API key not configured."

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            return f"VirusTotal request failed with status {response.status_code}"

        data = response.json()["data"]["attributes"]

        stats = data.get("last_analysis_stats", {})
        country = data.get("country", "unknown")
        asn = data.get("asn", "unknown")
        owner = data.get("as_owner", "unknown")

        return (
            f"VirusTotal IP Report for {ip}:\n"
            f"- Malicious: {stats.get('malicious', 0)}\n"
            f"- Suspicious: {stats.get('suspicious', 0)}\n"
            f"- Harmless: {stats.get('harmless', 0)}\n"
            f"- Undetected: {stats.get('undetected', 0)}\n"
            f"- Country: {country}\n"
            f"- ASN: {asn}\n"
            f"- Owner: {owner}"
        )

    except Exception as e:
        return f"Error querying VirusTotal: {str(e)}"

def cors_response(body, status_code=200):
    return {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "POST,OPTIONS"
        },
        "body": json.dumps(body)
    }


def lambda_handler(event, context):

    if event.get("httpMethod") == "OPTIONS":
        return cors_response("", 200)

    llm = ChatOpenAI(
        model="gpt-4.1-nano",
        temperature=0,
        api_key=os.environ["OPENAI_API_KEY"],
    )

    agent = create_react_agent(
        model=llm,
        tools=[reverse_text, utc_time, virustotal_ip_lookup],
    )
    print(f"Printing Event: {event}")
    body = json.loads(event.get("body", "{}"))
    question = body.get("question")
    print(f"Printing Question: {question}")

    # ✅ THIS IS THE ONLY VALID WAY
    result = agent.invoke({
        "messages": [
            {"role": "user", "content": question}
        ]
    })

    # Extract final model message
    answer = result["messages"][-1].content

    # 🔐 Save to DynamoDB
    item = {
        "requestId": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "question": question,
        "answer": answer,
        "sourceIp": event.get("requestContext", {})
                         .get("identity", {})
                         .get("sourceIp", "unknown")
    }

    table.put_item(Item=item)

    return {
        "statusCode": 200,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "OPTIONS,POST"
        },
        "body": json.dumps({
            "question": question,
            "answer": answer
        })
    }
