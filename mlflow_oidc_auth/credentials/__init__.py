"""Identity-provider credential generations and their rotation.

A provider's client credentials are versioned as *generations*: a login is started with one
generation and its callback may only exchange the code with that same generation, so a secret
rotated while the login is in flight can neither make the exchange fail with ``invalid_client``
nor tempt the callback into trying the new secret against a single-use code. This package owns
the encryption of stored secrets and the rotation protocol; the persistence lives in
``repository/credential_generation.py`` and the authlib client wiring in ``oauth.py``.
"""
