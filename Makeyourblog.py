import os
import jinja2
import webapp2
import re
import hmac
import random
import hashlib
from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
SECRET = 'imsosecret'

# these functions are used for password hashing and salt techniques
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name, password, salt)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
    
def users_key(group = 'default'):
    return db.Key.from_path('users' , group)
    

# Class blog is defined to store the blog details
class Blog(db.Model):
    subject = db.StringProperty(required = True)
    blog = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    createdBy = db.StringProperty()
    likedBy = db.IntegerProperty()
    dislikedBy = db.IntegerProperty()
    
# Class blog is defined to store the blog comments
class BlogComment(db.Model):
    blogId = db.StringProperty(required = True)
    comment = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    createdBy = db.StringProperty()
    
# Class blog is defined to store the User details
class UserInfo(db.Model,webapp2.RequestHandler):
    strname = db.StringProperty(required = True)
    strpassword = db.StringProperty(required = True)
    stremail = db.StringProperty()

   
    @classmethod
    def by_id(cls, uid):
        return UserInfo.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name, self):
        found = False
        u = UserInfo.all().filter('strname =', name)
        for user in u:
            found = True
            return user

    @classmethod
    def register(cls, name, password, email=None):
        strpassword = make_pw_hash(name, password)
        return UserInfo(parent = users_key(),
                        strname = name,
                        strpassword = strpassword,
                        stremai = email )

    @classmethod
    def login(cls, name , pw, self):
        u = cls.by_name(name, self)
        if u:
            hashstr = valid_pw(name,pw,u.strpassword)
            if hashstr:
                return u
        
# Class is defined to be inherited by all class to access the basic functions
class Handler(webapp2.RequestHandler):
    
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self,template,**params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_pw_hash(name, val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s , path =/' % (name, val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', make_secure_val(str(user.key().id())))

    def logout(self):
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id=;  path =/')

    def initialize(self,*a, **kw ):
        webapp2.RequestHandler.initialize(self,*a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and UserInfo.by_id(int(uid))
       
# Class is used to write new blog
class MainPage(Handler):
    def get(self):
        if self.user:
            self.render("NewBlog.html")
        else:
            self.redirect('/Userlogout')
            
    def post(self):
        subject = self.request.get("subject")
        blog = self.request.get("blog")
        createdBy = str(self.read_secure_cookie('user_id'))
        likedBy = 0
        dislikedBy = 0
        
        if subject and blog:
            t = Blog(subject=subject,blog=blog,createdBy=createdBy,likedBy=likedBy,dislikedBy=dislikedBy)
            blogKey = t.put()
            self.redirect("/showBlog?blogKey=" + str(blogKey.id()))
        else:
            error = "Please add subject and blog"
            self.render("NewBlog.html",error = error,subject=subject,blog=blog)

# Class is used to display new blog
class showNewBlog(Handler):
    def get(self):
        if self.user:
            blogkey = self.request.get("blogKey")
            query = Blog.get_by_id(int(blogkey))
            self.render("showNewBlog.html",query=query)
        else:
            self.redirect('/Userlogout')
            
# Class is used to display all blogs
class showAllBlog(Handler):
    def get(self):
        userid = self.read_secure_cookie('user_id')
        if self.user:
            query = db.GqlQuery("select * from Blog order by created desc limit 10")
            self.render("showAllBlogs.html",query=query,userid=userid)
        else:
            self.redirect('/Userlogout')

# Class is defined to allow the logged user to edit his own blog
class editBlog(Handler):
    def get(self,blogId):
        if self.user:
            query = Blog.get_by_id(int(blogId))
            self.render("editBlog.html",query=query)
        else:
            self.redirect('/Userlogout')

    def post(self,blogId):
        subject = self.request.get("subject")
        blog = self.request.get("blog")

        if subject and blog:
            t = Blog.get_by_id(int(blogId))
            t.subject = subject
            t.blog = blog
            t.put()
            self.redirect("/showBlog?blogKey=" + str(blogId))

# Class is defined to allow the logged user to delete his own blog
class deleteBlog(Handler):
    def get(self,blogId):
        if self.user:
            self.render("deleteBlog.html")
        else:
            self.redirect('/Userlogout')

    def post(self,blogId):
        if self.user:
            u = Blog.get_by_id(int(blogId))
            db.delete(u)
            self.render("DeleteConfirm.html")
        else:
            self.redirect('/Userlogout')

# Class is used to store the details of no of likes for a perticular blog
class likeBlog(Handler):
    def get(self,blogId):
        if self.user:
            u = Blog.get_by_id(int(blogId))
            if u.likedBy:
                u.likedBy = int(u.likedBy) + 1
                u.put()
            else:
                u.likedBy = 1
                u.put()
                
            self.redirect("/showBlog?blogKey=" + str(blogId))
        else:
            self.redirect('/Userlogout')

# Class is used to store the details of no of dislikes for a perticular blog
class dislikeBlog(Handler):
    def get(self,blogId):
        if self.user:
            u = Blog.get_by_id(int(blogId))
            if u.dislikedBy:
                u.dislikedBy = int(u.dislikedBy) + 1
                u.put()
            else:
                u.dislikedBy = 1
                u.put()
                
            self.redirect("/showBlog?blogKey=" + str(blogId))
        else:
            self.redirect('/Userlogout')

# Class is used to store the details of comments for a perticular blog
class commentBlog(Handler):
    def get(self,blogId):
        if self.user:
            query = BlogComment.all().filter('blogId =',str(blogId)).order('-created')
            self.render("commentBlog.html",blogId = str(blogId),query = query)
        else:
            self.redirect('/Userlogout')
    def post(self,blogId):
        if self.user:
            blogId = str(blogId)
            createdBy = str(self.read_secure_cookie('user_id'))
            comment = self.request.get("comment")

            u = BlogComment(blogId=blogId,comment=comment,createdBy=createdBy)
            u.put()

            self.redirect("/Blogs")
        else:
            self.redirect('/Userlogout')

# Class is used to store the details of new user
class UserSignup(Handler):
    def get(self):
        self.render("userBlogSignup.html")
        
    def post(self):
        strname = self.request.get("txtName")
        strpassword = self.request.get("txtpassword")
        strvarpassword = self.request.get("txtrepassword")
        stremail = self.request.get("txtemail")

        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        PWD_RE = re.compile(r"^.{3,20}$")
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        
        

        have_error = False

        params = dict(strname=strname, strpassword=strpassword, strvarpassword=strvarpassword, stremail=stremail)
        
        
        if not ( strname and USER_RE.match(strname)):
            params['msg'] = "That's not a valid user name.."
            have_error = True
        if not (strname and PWD_RE.match(strpassword)):
            params['pwdmsg'] = "That's not a valid password"
            have_error = True
        if strpassword != strvarpassword:
            params['varmsg'] = "verify password do not match"
            have_error = True
        if stremail != "" and not EMAIL_RE.match(stremail):
            params['emailmsg'] = "That's not a valid email"
            have_error = True
             
        if have_error:
            self.render("userBlogSignup.html", **params )
        else:
            u = UserInfo.by_name(strname, self)
            if u:
                params['msg']  = "User already exist!!"
                self.render("userBlogSignup.html", **params)
            else:
                u = UserInfo.register(strname, strpassword, stremail)
                u.put()

                self.login(u)
                self.redirect('/Blogs')

# Class is used to check the credentials of logged in user
class loginUser(Handler):
    def get(self):
        self.render("loginUser.html")

    def post(self):
        strname = self.request.get("txtName")
        strpassword = self.request.get("txtpassword")
        
        have_error = False

        params = dict(strname=strname, strpassword=strpassword)
        
        
        if not strname:
            params['msg'] = "Please enter User Name.."
            have_error = True
        if not strpassword :
            params['pwdmsg'] = "Please enter password.."
            have_error = True
        
        if have_error:
            self.render("loginUser.html", **params )
        else:
            u = UserInfo.login(strname,strpassword,self)
            if u:
                self.login(u)
                self.redirect('/Blogs')
            else:
                 params['msg'] = "Invalid login.."
                 self.render("loginUser.html", **params )       

# Class is used to display the welcome page to the logged in user
class welcomeUser(Handler):
    def get(self):
        username = self.request.cookies.get("UserName")
        userpassword = self.request.cookies.get("UserPwd")
        self.render("welcomeuser.html",username=username,userpassword=userpassword)

# Class is used to display the users details
class showUserInfo(Handler):
    def get(self):
        query = db.GqlQuery("select * from UserInfo")
        self.render("showUserInfo.html", query=query)
    def post(self):
        query = db.GqlQuery("Delete * from UserInfo where strname='" + UserName + "'")

# Class is used to allow the admin user to delete the user details
class DeleteUser(Handler):
    def get(self,UserName):
        u = UserInfo.by_name(str(UserName), self)
        db.delete(u)
        query =  db.GqlQuery("select * from UserInfo")
        self.render("showUserInfo.html", query=query)

# Class is used to allow the user to log out from the application
class Userlogout(Handler):
    def get(self):
        self.logout()
        self.redirect('/Userlogin')
   
app = webapp2.WSGIApplication([('/',MainPage),('/showBlog',showNewBlog),
                               ('/Blogs',showAllBlog),('/userSignup',UserSignup),
                               ('/welcome', welcomeUser),
                               ('/showUserInfo',showUserInfo),
                               ('/DeleteUser/([a-zA-Z0-9_-]{3,20})',DeleteUser),
                               ('/Userlogout',Userlogout),
                               ('/editBlog/([0-9]+)',editBlog),
                               ('/deleteBlog/([0-9]+)',deleteBlog),
                               ('/likeBlog/([0-9]+)',likeBlog),
                               ('/dislikeBlog/([0-9]+)',dislikeBlog),
                               ('/commentBlog/([0-9]+)',commentBlog),
                               ('/Userlogin',loginUser)],debug=True)
