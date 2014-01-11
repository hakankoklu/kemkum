import string
import hashlib
import random
import hmac
import re

SECRET = 'aysegul'

def hash_str(s):
	return hmac.new(SECRET,s).hexdigest()

def cookie_hash(s):
	return "%s|%s" % (s,hash_str(s))

def check_cookie_hash(h):
	val = h.split('|')[0]
	if h == cookie_hash(val):
		return val
	else:
		return None

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt=make_salt()
	h = hashlib.sha256(name + salt + pw).hexdigest()
	return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
	salt = h.split('|')[1]
	return h == make_pw_hash(name, pw, salt)

user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
pass_re = re.compile(r"^.{3,20}$")
email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def check_username(username):
    return user_re.match(username)

def check_password(password):
    return pass_re.match(password)

def check_email(email):
    return email_re.match(email)