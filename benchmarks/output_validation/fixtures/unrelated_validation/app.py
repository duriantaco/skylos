import json
import openai

client = openai.OpenAI()


def answer(question):
    settings = json.loads('{"ready": true}')
    response = client.chat.completions.create(  # ov-call: response
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": question}],
    )
    if settings["ready"]:
        return response.choices[0].message.content  # ov-use: result
