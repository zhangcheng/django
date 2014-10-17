"""
Django's standard crypto functions and utilities.
"""
import hmac
import hashlib
import time

# Use the system PRNG if possible
import random
try:
    random = random.SystemRandom()
    using_sysrandom = True
except NotImplementedError:
    import warnings
    warnings.warn('A secure pseudo-random number generator is not available '
		  'on your system. Falling back to Mersenne Twister.')
    using_sysrandom = False

from django.conf import settings
from django.utils.hashcompat import sha_constructor, sha_hmac


def salted_hmac(key_salt, value, secret=None):
    """
    Returns the HMAC-SHA1 of 'value', using a key generated from key_salt and a
    secret (which defaults to settings.SECRET_KEY).

    A different key_salt should be passed in for every application of HMAC.
    """
    if secret is None:
        secret = settings.SECRET_KEY

    # We need to generate a derived key from our base key.  We can do this by
    # passing the key_salt and our base key through a pseudo-random function and
    # SHA1 works nicely.

    key = sha_constructor(key_salt + secret).digest()

    # If len(key_salt + secret) > sha_constructor().block_size, the above
    # line is redundant and could be replaced by key = key_salt + secret, since
    # the hmac module does the same thing for keys longer than the block size.
    # However, we need to ensure that we *always* do this.

    return hmac.new(key, msg=value, digestmod=sha_hmac)

def get_random_string(length=12,
		      allowed_chars='abcdefghijklmnopqrstuvwxyz'
				    'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
    """
    Returns a securely generated random string.

    The default length of 12 with the a-z, A-Z, 0-9 character set returns
    a 71-bit value. log_2((26+26+10)^12) =~ 71 bits
    """
    if not using_sysrandom:
	# This is ugly, and a hack, but it makes things better than
	# the alternative of predictability. This re-seeds the PRNG
	# using a value that is hard for an attacker to predict, every
	# time a random string is required. This may change the
	# properties of the chosen random sequence slightly, but this
	# is better than absolute predictability.
	random.seed(
	    hashlib.sha256(
		("%s%s%s" % (
		    random.getstate(),
		    time.time(),
		    settings.SECRET_KEY)).encode('utf-8')
		).digest())
    return ''.join([random.choice(allowed_chars) for i in range(length)])


def constant_time_compare(val1, val2):
    """
    Returns True if the two strings are equal, False otherwise.

    The time taken is independent of the number of characters that match.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0
