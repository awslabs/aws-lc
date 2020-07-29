#!/usr/bin/env python3

import os
import typing


class EnvUtil(object):
    """An util helps get environment variable."""

    @staticmethod
    def get(key, defalut_value: typing.Optional[str] = None):
        val = os.environ.get(key)
        if val is None:
            val = defalut_value
        if val is None:
            raise ValueError("{} env variable is not set.".format(key))
        else:
            return val
