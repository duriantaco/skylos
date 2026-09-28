import openai
from external_schema import parse_result

client = openai.OpenAI()


def answer(question):
    response = client.chat.completions.create(  # ov-call: response
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": question}],
    )
    parsed = parse_result(response.choices[0].message.content)
    return parsed  # ov-use: result
