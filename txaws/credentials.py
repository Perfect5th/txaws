# Copyright (C) 2009 Robert Collins <robertc@robertcollins.net>
# Licenced under the txaws licence available at /LICENSE in the txaws source.

"""Credentials for accessing AWS services."""

import os

from txaws.util import hmac_sha1


__all__ = ['AWSCredentials']


ENV_ACCESS_KEY = "AWS_ACCESS_KEY_ID"
ENV_SECRET_KEY = "AWS_SECRET_ACCESS_KEY"


class AWSCredentials(object):

    def __init__(self, access_key="", secret_key=""):
        """Create an AWSCredentials object.

        @param access_key: The access key to use. If None the environment
            variable AWS_ACCESS_KEY_ID is consulted.
        @param secret_key: The secret key to use. If None the environment
            variable AWS_SECRET_ACCESS_KEY is consulted.
        """
        self.access_key = access_key
        self.secret_key = secret_key
        if not self.access_key:
            self.access_key = os.environ.get(ENV_ACCESS_KEY)
        if not self.access_key:
            raise ValueError("Could not find %s" % ENV_ACCESS_KEY)
        # perform checks for secret key
        if not self.secret_key:
            self.secret_key = os.environ.get(ENV_SECRET_KEY)
        if not self.secret_key:
            raise ValueError("Could not find %s" % ENV_SECRET_KEY)

    def sign(self, bytes):
        """Sign some bytes."""
        return hmac_sha1(self.secret_key, bytes)
