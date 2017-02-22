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

Check out `python-webnoti-example <https://github.com/puilp0502/python-webnoti-example>`_
for the full example.
