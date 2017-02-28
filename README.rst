python-webnoti
==============

Easy-to-use Python Web Push Notification Library

Installation
------------

Install with pip:

.. code:: sh

    $ pip install python-webnoti

Usage
-----

To send a notification:

.. code:: python

    from webnoti import send_notification, get_private_key

    send_notification(subscription, "Hello from server") # For Firefox
    send_notification(subscription, "Hello from server", # For Chrome
                      'mailto:admin@example.com', get_private_key('privkey.pem', generate=True))
    # subscription can be obtained from the client.

To manually generate private key:

.. code:: python

    from webnoti import get_private_key

    get_private_key('privkey.pem', b'password', generate=True)

This will generate private key named `privkey.pem` with password `password` (None if not encrypted) in current working directory.

Check out `python-webnoti-example <https://github.com/puilp0502/python-webnoti-example>`_
for the full example.
