import json
import openai
from pydantic import BaseModel


class Answer(BaseModel):
    text: str


client = openai.OpenAI()


def answer(question):
    response = client.chat.completions.create(  # ov-call: response
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": question}],
    )
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    validated = Answer.model_validate(parsed)
    return validated  # ov-use: result
