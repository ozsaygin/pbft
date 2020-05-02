# Author: Oguz Ozsaygin

from flask import Flask, request, jsonify
from flask_restful import Resource, Api, reqparse
import random
import hashlib

app = Flask(__name__)
api = Api(app)

peers = []

class Peers(Resource):
    def post(self):
        content = request.get_json()
        peers.append(content)
        return None, 201

    def get(self):
        return peers, 200

api.add_resource(Peers, "/peers")

if __name__ == "__main__":
    app.run(debug=True)
