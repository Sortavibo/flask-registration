import datetime
import re

import mongoengine

class User(mongoengine.Document):
    meta = {
        'collection': 'users',
        'indexes': ['active', 'username'],
        'index_background': True,
    }
    username = mongoengine.StringField(required=True, unique=True, validation=is_word)
    email = mongoengine.EmailField(required=True, unique=True)
    password = mongoengine.StringField(required=True)
    active = mongoengine.BooleanField(default=False)
    time_added = mongoengine.DateTimeField(default=datetime.datetime.now)
    time_updated = mongoengine.DateTimeField(default=datetime.datetime.now)
