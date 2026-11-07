import pickle
from flask import Flask, request
app = Flask(__name__)
class DataParser:
    def loads(self, data):
        return data.decode("utf-8")
@app.post("/decode")
def decode():
    pickle = DataParser()
    return pickle.loads(request.data)
