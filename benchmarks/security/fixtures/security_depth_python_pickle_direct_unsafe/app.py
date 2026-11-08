import pickle
from flask import Flask, request
app = Flask(__name__)
@app.post("/decode")
def decode():
    return str(pickle.loads(request.data))
