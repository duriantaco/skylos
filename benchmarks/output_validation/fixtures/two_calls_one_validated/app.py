import json
import openai

client = openai.OpenAI()


def answer(first_question, second_question):
    first = client.chat.completions.create(  # ov-call: first
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": first_question}],
    )
    second = client.chat.completions.create(  # ov-call: second
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": second_question}],
    )
    first_parsed = json.loads(first.choices[0].message.content)
    print(first_parsed)  # ov-use: first-result
    print(second.choices[0].message.content)  # ov-use: second-result
