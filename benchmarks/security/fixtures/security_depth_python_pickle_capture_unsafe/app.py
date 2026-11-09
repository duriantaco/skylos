import pickle
load_record = pickle.loads
from flask import Flask, request
app = Flask(__name__)
@app.post("/decode")
def decode():
    return str(load_record(request.data))
