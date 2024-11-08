from datetime import date
from flask import Flask, request, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, Table, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
# 로그인 메니저 생성
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # User.get 속성이 없어서 query 사용
    return User.query.get(user_id)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# TODO: Create a User table for all your registered users. 
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")
    
    email = db.Column(db.String(250), unique=True)
    password = db.Column(db.String(250))
    name = db.Column(db.String(100))

# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250),nullable=False )
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

# Comment 테이블 configure
class Comment(db.Model):
    __tablename__ = "comments"
    
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=True)
    
    # User 모델과의 관계
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    comment_author = relationship("User", back_populates="comments")
    # BlogPost 모델과의 관계
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")
    
    
with app.app_context():
    # db.drop_all()
    db.create_all()

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        
        # 등록할 이메일이 존재하는지 확인한다.
        if User.query.filter_by(email=form.email.data).first():
            flash("Email address is already existed!")
            return redirect(url_for('login'))
        
        #패스워드 해싱한다.
        hashed_and_salted_password = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8,
            )
        
        # user에 전달된 form data를 넣는다.
        user = User(
            email = form.email.data,
            password = hashed_and_salted_password,
            name = form.name.data,
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("Register and log in Successful.")
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("Log in Successful!")
                return redirect(url_for('get_all_posts', user_id=user.id))
            elif not user:
                flash("Email is not matched!", 'danger')
                return redirect(url_for('login'))
            else:
                flash("Password is not matched!", 'danger')
                return redirect(url_for('login'))
    
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for('login'))
        
        comment = Comment(
            text = form.comment.data,
            author = current_user,
            parent_post = requested_post,              
        )
        db.session.add(comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, form=form, current_user=current_user)

# 데코레이터 생성
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.id == 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            author_id=current_user.id,
            author=current_user.name,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user.name
        post.author_id = current_user.id
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
