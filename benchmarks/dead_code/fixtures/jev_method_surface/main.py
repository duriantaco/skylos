import asyncio
import importlib
import json
from pathlib import Path


async def replay():
    plan = json.loads(Path(__file__).with_name("topics.json").read_text())
    queue = asyncio.Queue()
    for topic in plan["published"]:
        await queue.put(topic)

    handlers = importlib.import_module("handlers")
    results = []
    while not queue.empty():
        topic = await queue.get()
        callback = getattr(handlers, "on_" + topic)
        results.append(await callback())
    return results


if __name__ == "__main__":
    print(asyncio.run(replay()))
