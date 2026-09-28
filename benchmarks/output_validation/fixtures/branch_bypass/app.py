import json
import openai

client = openai.OpenAI()


def answer(question, check):
    response = client.chat.completions.create(  # ov-call: response
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": question}],
    )
    raw = response.choices[0].message.content
    if check:
        result = json.loads(raw)
    else:
        result = raw
    return result  # ov-use: result
