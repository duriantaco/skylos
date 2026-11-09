calculate_expression = eval
from flask import Flask, request
app = Flask(__name__)
@app.post("/calculate")
def calculate():
    return str(calculate_expression(request.data.decode()))
