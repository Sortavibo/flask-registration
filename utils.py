import requests

from flask import abort, current_app, render_template
from flask_babel import gettext

from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature


def send_with_mailgun(
    email: str,
    confirm_url: str,
    subject: str, *,
    content_type: str = 'text/html',
):
    data = {
        'from': 'test@mail.ru',
        'to': recipients,
        'subject': subject,
        'html': confirm_url,
        'h:Content-Type': content_type,
        'h:Precedence': 'bulk',
    }

    request_kwargs = {
        'timeout': 40,
        'auth': ('api', current_app.config['MAILGUN_TOKEN']),
        'data': data,
        'verify': False,
    }

    return requests.post(current_app.config['MAILGUN_URL'], **request_kwargs)


def generate_confirmation_token(email: str):
    """Confirmation url token."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['PASSWORD_SALT'])


def send_email(email: str, type: str):
    token = generate_confirmation_token(email)
    if type == 'change_password':
        link = current_app.config['LINK_FOR_CHANGE_PASSWORD']
        subject = gettext('Password changing')
    elif type == "registration":
        link = current_app.config['LINK_FOR_CONFIRMATION']
        subject = gettext('Registration')

    confirm_url = f'{link}{token}'

    send_with_mailgun(email, confirm_url, subject)

    return token


def confirm_token(token: str, *, expiration=3600):
    """check token."""
    serializer = URLSafeTimedSerializer(
        current_app.config['SECRET_KEY']
    )
    try:
        email = serializer.loads(
            token,
            salt=current_app.config['PASSWORD_SALT'],
            max_age=expiration
        )
    except (BadSignature, SignatureExpired):
        abort(400, gettext('This token is no longer valid'))
    return email
