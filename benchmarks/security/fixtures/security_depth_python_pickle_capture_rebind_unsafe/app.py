import pickle
import json
load_record = pickle.loads
pickle = json
from flask import Flask, request
app = Flask(__name__)
@app.post("/decode")
def decode():
    return str(load_record(request.data))
