from openai import OpenAI


client = OpenAI(api_key="test-key")


def summarize_ticket(ticket):
    return client.responses.parse_json(
        model="gpt-4.1-mini",
        input=ticket["body"],
        schema={
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "severity": {"type": "string"},
            },
            "required": ["summary", "severity"],
        },
    )
