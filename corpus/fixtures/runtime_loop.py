def drain(items):
    while items:
        items.pop()
    return len(items)


print(drain([1]))
