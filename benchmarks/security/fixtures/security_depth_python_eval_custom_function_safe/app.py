from flask import Flask, request
app = Flask(__name__)
def eval(text):
    return text
@app.post("/calculate")
def calculate():
    return eval(request.data.decode())
