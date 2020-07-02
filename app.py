import os

from flask import Flask
from flask_mongoengine import MongoEngine
from flask_security import Security, MongoEngineUserDatastore, current_user
from flask_cors import CORS
from flask_babel import Babel

from models import User
from registration import registration_blueprint
from limiter import limiter


app = Flask(__name__)

app.db = MongoEngine(app)
app.user = MongoEngineUserDatastore(app.db, User)
app.security = Security(app, app.user)


limiter._storage_uri = f'{app.config["STORAGE"]}'
limiter.init_app(app)

app_blueprints = [
    registration_blueprint,
]

for blueprint in app_blueprints:
    app.register_blueprint(blueprint)

CORS(app, origins='*', supports_credentials=True)