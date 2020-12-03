from flask import *
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from os import environ
import jwt
import datetime


route = '/v1'
app = Flask(__name__)

#DB settings
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
"""
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://{user}:{passwd}@{host}:{port}/{db}'.format(
        user='dbuser',
        passwd='postgres',
        host='0.0.0.0',
        port='5432',
        db='user-db')
"""
app.config['SQLALCHEMY_DATABASE_URI'] = environ['DB_URI']
db = SQLAlchemy(app)

# TODO: load it from env file or server
app.config['SECRET_KEY'] = 'TOP-SECRET_KEY'

# models
class User(db.Model):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String)
    password_hash = db.Column(db.String)
    created_on = db.Column(db.String)

    def __init__(self, email, password):
        self.email = email
        self.password_hash = self.create_pwd_hash(password)
        self.created_on = str(datetime.datetime.utcnow())

    def create_pwd_hash(self, password):
        pwd_hash = Bcrypt(app).generate_password_hash(password).decode('utf-8')
        return pwd_hash

    def check_password(self, password):
        return Bcrypt(app).check_password_hash(self.password_hash, password)

    def authenticate(self, password):
        if self.check_password(password):
            token = {'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),
                    'iat' : datetime.datetime.utcnow(),
                    'sub' : self.user_id}
            return jwt.encode(token, app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')
        else:
            return None

    @staticmethod
    def decode_token(token):
        if 'Bearer ' in token:
            token = token.replace('Bearer ', '')
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidSignatureToken:
            return 'Invalid token. Please log in again.'
        
    def to_dict(self):
        tmp = {'user_id': self.user_id,
                'email': self.email,
                'created_on': self.created_on}
        return tmp


class Relations(db.Model):
    __tablename__ = 'relations'

    relation_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    follower = db.Column(db.Integer)
    following = db.Column(db.Integer)
    created_on = db.Column(db.String)

    def __init__(self, follower_id, following_id):
        self.follower = follower_id
        self.following = following_id
        self.created_on = str(datetime.datetime.utcnow())

    def to_dict(self):
        tmp = {'relation_id' : self.relation_id,
                'follower': self.follower,
                'following': self.following}
        return tmp

# views
@app.route(route + '/user', methods=['POST'])
def add_user():
    """
    This method registers new user and returns authentication token. If the users alredy exists it returns an error.
    :post_data: json {'email', 'password'}
    :return: json {'token'}}
    """
    email = request.json['email']
    password = request.json['password']

    user = User.query.filter_by(email=email).first()
    print(user)
    if user is not None:
        # User already exists
        return make_response({'msg': 'User already exists.'})

    # Create new user
    user = User(email, password)
    db.session.add(user)
    db.session.commit()

    token = user.authenticate(password)

    return make_response({'msg': 'Created new user.', 'token': token})


@app.route(route + '/user', methods=['GET'])
def login_user():
    """
    This method logs in an existing user.
    :return: json {'auth_token'}
    """
    email = request.json['email']
    password = request.json['password']

    user = User.query.filter_by(email=email).first()
    if user is None:
        # User does not exist
        return make_response({'msg': 'User does not exist.'})

    token = user.authenticate(password)
    if token is None:
        # wrong password
        return make_response({'msg': 'Password is incorrect.'})

    return make_response({'msg': 'Login successful', 'token': token})


# to ne vem ce rabimo
@app.route(route + '/user/check', methods=['GET'])
def check_token():
    token = request.headers.get('Authorization')
    # checks if token is ok
    token = request.headers.get('Authorization')
    user_id = User.decode_token(token)
    return make_response({'msg': 'ok', 'user_id': user_id})


@app.route(route + '/follow', methods=['GET'])
def get_relations():
    """
    Returns users followers and following.
    :return: json {followers: [], following: []}
    """
    token = request.headers.get('Authorization')
    login_user = User.decode_token(token)
    followers = Relations.query.filter_by(following=login_user).all()
    following = Relations.query.filter_by(follower=login_user).all()
    return make_response({'msg': 'ok',
                        'followers': [{'user_id': x.follower} for x in followers],
                        'following':[{'user_id': x.following} for x in following]})
        


@app.route(route + '/follow/<user_id>', methods=['POST'])
def follow_user(user_id):
    token = request.headers.get('Authorization')
    login_user = User.decode_token(token)
    relation = Relations(login_user, user_id) 
    db.session.add(relation)
    db.session.commit()
    return make_response({'msg': 'ok'})


@app.route(route + '/follow/<user_id>', methods=['DELETE'])
def unfollow_user(user_id):
    token = request.headers.get('Authorization')
    login_user = User.decode_token(token)
    db.session.query(Relations).filter(Relations.follower==login_user).filter(Relations.following==user_id).delete()
    db.session.commit()
    return make_response({'msg': 'ok'})
    

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='8080')

