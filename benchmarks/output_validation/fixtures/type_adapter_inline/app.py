import openai
from pydantic import BaseModel, TypeAdapter


class Answer(BaseModel):
    text: str


client = openai.OpenAI()


def answer(question):
    response = client.chat.completions.create(  # ov-call: response
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": question}],
    )
    raw = response.choices[0].message.content
    return TypeAdapter(Answer).validate_json(raw)  # ov-use: result
