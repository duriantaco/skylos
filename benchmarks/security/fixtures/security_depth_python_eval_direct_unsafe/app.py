from flask import Flask, request
app = Flask(__name__)
@app.post("/calculate")
def calculate():
    return str(eval(request.data.decode()))
