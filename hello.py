import email
from flask import Flask, request, Response
import datetime
import redis
from flask_sqlalchemy import SQLAlchemy
import os
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import click
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////' + os.path.join(app.root_path, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = 'dev'

r=redis.StrictRedis(host='localhost',port=6379,db=0,decode_responses=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(30))
    username = db.Column(db.String(20))
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def validate_password(self, password):
        return check_password_hash(self.password_hash, password)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        content = request.get_json(silent=True)
        username = content['username']
        if User.query.filter_by(username=username).first():
            return 'The name you chose is registered.'
        password = content['password']
        email = content['email']
        user = User(username = username, email = email)
        user.set_password(password) 
        db.session.add(user)
        db.session.commit()
    return F"{username}, has been successfully created"

login_manager = LoginManager(app)  
login_manager.login_view = 'login'
@login_manager.user_loader
def load_user(user_id):  
    user = User.query.get(int(user_id))
    print(user_id)
    return user 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.get_json(silent=True)
        username = user['username']
        password = user['password']

        if not username or not password:
            return 'enter your username or password'

        if User.query.filter_by(username = username).first():
            user = User.query.filter_by(username = username).first()
            if user.validate_password(password):
                login_user(User.query.filter_by(username=username).first())
                print(current_user.is_authenticated)
                return current_user.username

    return 'Invalid username or password.'

@app.route('/logout')
@login_required 
def logout():
    logout_user()
    return 'logout'


def event_stream():
    pubsub=r.pubsub()
    pubsub.subscribe('chat')
    for message in pubsub.listen():
        yield 'data:{}\n\n'.format(message['data'])

@app.route('/send',methods=['POST'])
def post():
    if current_user.is_authenticated:
        message = request.get_json()['message']
        user = current_user.username
        now = datetime.datetime.now().replace(microsecond=0).time()
        r.publish('chat', u'[%s] %s: %s' %(now.isoformat(), user, message))
        return Response(status = 2)
    return Response(status = 1)



@app.route('/stream')
def stream():
    return Response(event_stream(),mimetype='text/event-stream')

@app.cli.command()
@click.option('--username', prompt=True, help='The username used to login.')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='The password used to login.')
@click.option('--email', prompt=True, help='email')
def admin(password, email, username):
    """Create user."""
    db.create_all()

    click.echo('Creating user...')
    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo('Done.')

    

if __name__ == '__main__':
    app.run(debug=True)
