from base64 import urlsafe_b64encode as b64encode, urlsafe_b64decode as b64decode
from datetime import datetime, timedelta
from urllib import parse

from cryptography.hazmat.primitives.asymmetric import ec
import jwt
import requests

from .utils import fill_padding
from .encryption import encrypt_data


class Notification(object):
    TTL = 300  # Time to live in seconds (in push service)
    expire_after = 86400  # JWT Token will expire after this seconds
    vapid_private_key = None  # Server private key used to generate applicationServerKey
    sender = 'mailto:root@localhost'  # Sender of the notification, either in mailto: URI or generic URL

    def __init__(self, subscription, message=None, claims=None, ttl=None, private_key=None, generate_claims=True):
        """
        Initialize a Notification instance using given parameters.

        :param subscription: PushSubscription object which can be obtained from client.
        :type subscription: dict
        :param message: Message to send
        :type message: str or bytes
        :param claims: VAPID claims
        :type claims: dict
        :param private_key: Server private key used to sign VAPID claims.
        :type private_key: ec.EllipticCurvePrivateKey
        :param ttl: Time to live (in push service)
        :type ttl: int
        """
        try:
            self.endpoint = subscription['endpoint']
            self.p256dh = b64decode(fill_padding(subscription['keys']['p256dh']))
            self.auth_secret = b64decode(fill_padding(subscription['keys']['auth']))
        except KeyError as e:
            raise KeyError('Missing key in subscription object: %r' % e.args[0])

        if type(message) is bytes:
            self.message = message
        else:
            try:
                self.message = message.encode('utf-8')
            except AttributeError:
                raise TypeError('%r must be bytes or str' % message)

        if private_key is not None:
            self.vapid_private_key = private_key

        if claims is None:
            if generate_claims:
                assert self.vapid_private_key is not None, 'You must set Notification.private_key to use VAPID.\n' \
                                                     'You can generate one using get_private_key.'
                self.claims = self.generate_claims()
            else:
                # Do not use VAPID Authentication
                self.claims = None
        else:
            assert self.vapid_private_key is not None, 'You must set Notification.private_key to use VAPID.\n' \
                                                 'You can generate one using get_private_key.'
            self.claims = claims

        if ttl is not None:
            self.TTL = ttl

    def generate_claims(self):
        parsed_endpoint = parse.urlparse(self.endpoint)
        expires_at = (datetime.now() + timedelta(seconds=self.expire_after)).timestamp()
        return {
            'aud': parsed_endpoint.scheme + '://' + parsed_endpoint.netloc,
            'exp': str(int(expires_at)),
            'sub': self.sender
        }

    def send(self):
        headers, ciphertext = encrypt_data(self.p256dh, self.auth_secret, self.message)
        headers['TTL'] = str(self.TTL)
        if self.claims is not None:
            vapid_public_key_b64 = b64encode(self.vapid_private_key.public_key().public_numbers().encode_point())
            vapid = sign_vapid(self.claims, self.vapid_private_key)
            headers['Authorization'] = 'WebPush ' + vapid
            headers['Crypto-Key'] += '; p256ecdsa=' + vapid_public_key_b64.decode('utf-8').strip('=')
        import pprint
        pprint.pprint(headers)
        return requests.post(self.endpoint, headers=headers, data=ciphertext)


def sign_vapid(claims, private_key):
    """
    Sign a VAPID claims using given private key.

    :param claims: Dictionary of claims to sign.
    :type claims: dict
    :param private_key: Server's private key used to sign claims.
    :type private_key: ec.EllipticCurvePrivateKey
    :return: Encoded VAPID in str
    """
    return jwt.encode(claims, private_key, algorithm="ES256").decode('utf-8')


def send_notification(subscription, data, sender=None, private_key=None):
    """
    A wrapper function for initializing & sending notification.

    :param subscription: client's subscription
    :param data: An actual data to send
    :param sender: (Optional) VAPID claims sender
    :param private_key: (Optional) VAPID private key
    :return: Response object received from Push Service
    """
    noti = Notification(subscription, data, private_key=private_key, generate_claims=False)
    if sender is not None:
        noti.claims['sub'] = sender

    return noti.send()
