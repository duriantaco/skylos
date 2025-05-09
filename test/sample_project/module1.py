## module1.py
def used_function():
    """This function is called elsewhere."""
    return "I'm used!"

def unused_function():
    """This function is never called."""
    return "I'm unused!"

def main():
    result = used_function()
    print(result)

if __name__ == "__main__":
    main()