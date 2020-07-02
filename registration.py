from flask import abort, current_app, Blueprint
from flask_restplus import Resource, Api
from flask_security import auth_token_required, current_user
from flask_security.utils import verify_password, hash_password
from flask_babel import gettext

from mongoengine.queryset.visitor import Q
from mongoengine.errors import NotUniqueError
from webargs.flaskparser import use_args
from webargs import fields
from itsdangerous import URLSafeSerializer
from marshmallow import validate

from models import User
from utils import (
    send_email,
    confirm_token,
)
from limiter import limiter


registration_blueprint = Blueprint('registration', __name__)

api = Api(registration_blueprint, prefix='/registration', doc=False)


@api.route('/sign_in')
class AuthResource(Resource):

    @use_args({
        'username': fields.String(required=True),
        'password': fields.String(required=True)
    })
    def post(self, input_values: dict):
        user = User.objects(
            Q(active=True) & (
                Q(username=input_values['username']) | Q(email=input_values['username'])
            )
        ).first()

        if user is None or not verify_password(input_values['password'], user.password):
            abort(400, gettext('Incorrect data'))

        return {
            'status': 'success',
            'token': user.get_auth_token(),
        }


sign_up_kwargs = {
    'username': fields.String(required=True, validate=validate.Regexp('^[a-zA-Z0-9_]*$')),
    'email': fields.Email(required=True),
    'password': fields.String(validate=validate.Length(min=10), required=True)
}


@api.route('/sign_up')
class RegistrationResource(Resource):

    decorators = [limiter.limit('5/hour')]

    @use_args(sign_up_kwargs)
    def post(self, input_values: dict):
        input_values['password'] = hash_password(input_values['password'])
        language = input_values.pop('language')
        try:
            current_app.user.create_user(**input_values)
        except NotUniqueError:
            abort(400, gettext('User with this name or email already exists'))
        send_email(
            input_values['email'],
            'registration',
        )
        return {
            'status': 'success',
            'message': gettext('User successfully created. Check your inbox.'),
        }

@api.route('/change_password')
class ChangePasswordResource(Resource):

    method_decorators = [auth_token_required]

    @use_args({
        'password': fields.String(required=True),
        'password_confirm': fields.String(required=True),
    })
    def post(self, input_values: dict):
        if input_values['password'] != input_values['password_confirm']:
            abort(400, gettext('Password and confirmation value not match'))

        current_user.password = hash_password(input_values['password'])
        current_user.save()

        return {
            'status': 'success',
            'message': gettext('Password was changed'),
            'token': current_user.get_auth_token(),
        }


@api.route('/registration_confirmation')
class RegistrationConfirmationResource(Resource):

    @use_args({'token': fields.String(required=True)})
    def post(self, input_values: dict):
        email = confirm_token(input_values['token'])
        user = User.objects(email=email).first()
        if user:
            if user.active is True:
                abort(400, gettext('User is active.'))
            user.update(active=True)
            return {
                'status': 'success',
                'message': gettext('Confirmation was successful.'),
            }
        else:
            abort(400, gettext('Invalid token.'))


@api.route('/repeat_confirmation')
class RepeatConfirmationResource(Resource):

    @use_args({'email': fields.Email(required=True)})
    def post(self, input_values: dict):
        user = User.objects(email=input_values['email'], active=False).first()
        if not user:
            abort(400, gettext('You do not need activation'))
        else:
            send_email(
                input_values['email'],
                'registration'
            )
        return {
            'status': 'success',
            'message': gettext('Check your inbox for confirmation email'),
        }


@api.route('/forget_password')
class ForgetPasswordResource(Resource):

    decorators = [limiter.limit('5/hour')]

    @use_args(confirmation_args)
    def post(self, input_values: dict):
        user = User.objects(email=input_values['email']).first()
        if user:
            send_email(
                input_values['email'],
                'change_password'
            )
        else:
            abort(400, gettext('This user does not exist'))

        return {
            'status': 'success',
            'message': gettext('Check your inbox for confirmation email'),
        }


@api.route('/forget_password_confirmation')
class ForgetPasswordConfirmationResource(Resource):

    @use_args({
        'token': fields.String(required=True),
        'password': fields.String(validate=validate.Length(min=8), required=True)
    })
    def post(self, input_values: dict):
        email = confirm_token(input_values['token'])
        user = User.objects(email=email).first()
        if user:
            user.password = hash_password(input_values['password'])
            user.save()

            return {
                'status': 'success',
                'message': gettext('Password was changed.')
            }
        else:
            abort(400, gettext('Invalid confirmation token.'))
