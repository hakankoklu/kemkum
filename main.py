import os
import webapp2
import wiki_util
import jinja2
import time
import datetime
import json

from google.appengine.api import memcache
from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)
jinja_env_html = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False)



class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str_html(self, template, **params):
        t = jinja_env_html.get_template(template)
        return t.render(params)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render_html(self, template, **params):
        self.write(self.render_str_html(template, **params))
    def render(self, template, **params):
        self.write(self.render_str(template, **params))
    def check_username_cookie(self):
        self.response.headers['Content-Type'] = 'text/plain'
        username_cookie_str = self.request.cookies.get('username')
        self.response.headers['Content-Type'] = 'text/html'
        if not username_cookie_str:
            return None
        else:
            username_sent = wiki_util.check_cookie_hash(username_cookie_str)
            if username_sent:
                return username_sent
            else:
                return None


last_front_update = time.time()
last_single_update = time.time()

def front_posts(update = False):
    global last_front_update
    key = 'front'
    blogs = memcache.get(key)
    if blogs is None or update:
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        last_front_update = time.time()
        blogs = list(blogs)
        memcache.set(key, blogs)
    return blogs

def single_post(post_id):
    global last_single_update
    key = str(post_id)
    single_post = memcache.get(key)
    if single_post is None:
        single_post = db.GqlQuery("SELECT * FROM Blog WHERE post_id = " + str(post_id)).get()
        last_single_update = time.time()
        memcache.set(key, single_post)
    return single_post

class User(ndb.Model):
    username = ndb.StringProperty(required = True)
    password = ndb.StringProperty(required = True)

class Wiki(ndb.Model):
    wikipath = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    edited = ndb.DateTimeProperty(auto_now = True)

class AllPage(Handler):
    def get(self):
        wiki_items = Wiki.query()
        wikis = list(wiki_items)
        self.render_html("allwiki.html", wikis = wikis)
        
class WikiPage(Handler):
    def get(self, wikipath=""):
        if wikipath == "":
            wikipath = "/__root__"
        username = self.check_username_cookie()
        top_menu = "Login"
        logged = ""
        if username:
            logged = "logged"
        wikipath = wikipath[1:len(wikipath)]
        wiki_item = Wiki.query(Wiki.wikipath == wikipath).get()
        if wiki_item:
            created = wiki_item.created.strftime("%c")
            updated = wiki_item.edited.strftime("%c")
            if wikipath == "__root__":
                self.render_html("wiki.html", content = wiki_item.content, logged = logged,
                created = created, updated = updated, username = username, wikipath = "")
            else:
                self.render_html("wiki.html", content = wiki_item.content, logged = logged,
                created = created, updated = updated, username = username, wikipath = wikipath)
        else:
            if wikipath == "__root__":
                self.redirect("/_edit/")
            else:
                self.redirect("/_edit/"+wikipath)

class EditPage(Handler):
    def get(self, wikipath=""):
        if wikipath == "/":
            wikipath = "/__root__"
        username = self.check_username_cookie()
        wikipath = wikipath[1:len(wikipath)]
        wiki_item = Wiki.query(Wiki.wikipath == wikipath).get()
        content = ""
        top_menu = "Login"
        logged = ""
        if username:
            logged = "logged"
        if username and wiki_item:
            content = wiki_item.content
        elif not (username or wiki_item):
            self.redirect("/login")
        if wikipath == "__root__":
            self.render("edit_wiki.html", content = content, logged = logged, username = username, 
            wikipath = "")
        else:
            self.render("edit_wiki.html", content = content, logged = logged, username = username, 
            wikipath = wikipath)

    def post(self, wikipath=""):
        if wikipath =="/":
            wikipath = "/__root__"
        wikipath = wikipath[1:len(wikipath)]
        print wikipath + " from post"
        content = self.request.get("content")
        print content
        wiki_item = Wiki.query(Wiki.wikipath == wikipath).get()

        if wiki_item:
            wiki_item.content = content
            wiki_item.put()
        else:
            w = Wiki(wikipath = wikipath, content = content)
            w.put()
            print "data entered"
            time.sleep(0.03)
        if wikipath == "__root__":
            self.redirect("/")
        else:
            self.redirect("/"+wikipath)
            #redirect to post later!!
        
class SignupPage(Handler):
    def get(self):
        username_sent = self.check_username_cookie()
        if not username_sent:
            self.render("signup.html", username = "", username_error = "", 
                pass_error = "", verify_error = "", email = "", email_error ="")
        else:
            self.redirect("/")

    def post(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        user_check = wiki_util.check_username(username)
        pass_check = wiki_util.check_password(password)
        verify_check = password == verify
        email_check = wiki_util.check_email(email)
        user_taken = False

        current_user = User.query(User.username == username).get()
        if current_user:
            user_taken = True

        username_error, password_error, verify_error, email_error = '','','','' 
        if not (user_check and not user_taken and pass_check and verify_check and (email == '' or email_check)):
            if not user_check:
                username_error = 'Invalid username'
            elif user_taken:
                username_error = 'Username taken'
            if not pass_check:
                password_error = 'Invalid password'
            elif not verify_check:
                verify_error = 'Passwords do not match'
            if email and not email_check:
                email_error = 'Invalid email'
            self.render("signup.html", username = username, email = email, 
                username_error = username_error, pass_error = password_error, 
                verify_error = verify_error, email_error = email_error)
        else:
            new_cookie = wiki_util.cookie_hash(username)
            self.response.headers.add_header('Set-Cookie', str('username = %s; Path=/' % new_cookie))
            u = User(username = username, password = wiki_util.make_pw_hash(username, password))
            u.put()
            self.redirect("/")

class LoginPage(Handler):
    def get(self):
        username_sent = self.check_username_cookie()
        if not username_sent:
            self.render("login.html", username = "", username_error = "", 
                pass_error = "")
        else:
            self.redirect("/")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        
        current_user = User.query(User.username == username).get()
        valid_user = current_user != None
        valid_pass = False
        if valid_user:
            valid_pass = wiki_util.valid_pw(username, password, current_user.password)
                
        username_error, password_error= '',''
        if not valid_pass:
            login_error = 'Invalid username or password'
            self.render("login.html", username = username, login_error = login_error)
        else:
            new_cookie = wiki_util.cookie_hash(username)
            self.response.headers.add_header('Set-Cookie', str('username = %s; Path=/' % new_cookie))
            self.redirect("/")

class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
        self.redirect("/")

class Bulkdelete(Handler):
    def get(self):
        self.response.out.write("deleted!!")
        try:
            while True:
                q = db.GqlQuery("SELECT __key__ FROM Blog")
                assert q.count()
                db.delete(q.fetch(200))
                time.sleep(0.5)
        except Exception, e:
            self.response.out.write(repr(e)+'\n')
            pass

class FlushCache(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect("/")        

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
application = webapp2.WSGIApplication([
    ('/', WikiPage),
    ('/_all', AllPage),
    ('/delete', Bulkdelete),
    ('/signup', SignupPage),
    ('/login', LoginPage),
    ('/logout', LogoutPage),
    ('/_edit' + PAGE_RE, EditPage),
    (PAGE_RE, WikiPage),
    ('/flush', FlushCache)
], debug=True)

