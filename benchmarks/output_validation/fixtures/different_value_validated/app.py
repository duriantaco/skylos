import json
import openai

client = openai.OpenAI()


def answer(question, fallback):
    response = client.chat.completions.create(  # ov-call: response
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": question}],
    )
    json.loads(fallback)
    return response.choices[0].message.content  # ov-use: result
