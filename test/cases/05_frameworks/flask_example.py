from flask import Flask, Blueprint

app = Flask(__name__)
bp = Blueprint("bp", __name__)

# dead 
def helper_dead():     
    return 1

# used
@app.route("/root")
def root():
    return "root"       

# used
@bp.route("/hi")
def hi():
    return "hi"         

app.register_blueprint(bp, url_prefix="/v1")

if __name__ == "__main__":
    app.run(debug=True)