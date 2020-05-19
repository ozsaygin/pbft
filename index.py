# Author: Oguz Ozsaygin

from flask import Flask, request, jsonify
from flask_restful import Resource, Api, reqparse
import random
import hashlib

app = Flask(__name__)
api = Api(app)

peers = []
malicous_peers = []
blocks = []

class Peers(Resource):
    def post(self):
        content = request.get_json()
        peers.append(content)
        return None, 201

    def get(self):
        return peers, 200

class PeersPid(Resource):
    def get(self, pid):
        for p in peers:
            if p['pid'] == int(pid):
                return p, 200
        
class AppyMalicious(Resource):
    def post(self):
        content = request.get_json()
        threshold = content['k']
        if len(malicous_peers) < threshold: # be malicous
            malicous_peers.append(content)
            return {'status': 'malicous'}, 201
        else: # be honest
            return {'status' : 'honest'}, 201

class FakeBlock(Resource):
    def post(self):
        content = request.get_json()
        block = content['block']
        if len(blocks) == 0: # be malicous
            blocks.append(block)
        return {'block': blocks[0]}, 201

api.add_resource(Peers, "/peers")
api.add_resource(PeersPid, "/peers/<pid>")
api.add_resource(AppyMalicious, "/applymalicous")
api.add_resource(FakeBlock, "/fakeblock")

if __name__ == "__main__":
    app.run(debug=True)
