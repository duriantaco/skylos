import openai

client = openai.OpenAI()


def answer(question):
    response = client.chat.completions.create(  # ov-call: response
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": question}],
    )
    items = [response.choices[0].message.content]
    return items[0]  # ov-use: result
