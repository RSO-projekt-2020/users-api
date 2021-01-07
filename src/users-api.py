from flask import *
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from os import environ
import jwt
import datetime
import consul

# logging imports
import logging
from logstash_async.handler import AsynchronousLogstashHandler
from logstash_async.handler import LogstashFormatter

# healthcheck imports
from healthcheck import HealthCheck

route = '/v1'
app = Flask(__name__)
CORS(app, resources={r"/v1/*": {"origins": "*"}})

# -------------------------------------------
# DB settings
# -------------------------------------------
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
consul_env = consul.Consul(host='azure-consul-server', port=8500)

# TODO: load it from env file or server
app.config['SECRET_KEY'] = 'TOP-SECRET_KEY'

# -------------------------------------------
# Logging setup
# -------------------------------------------
# Create the logger and set it's logging level
logger = logging.getLogger("logstash")
logger.setLevel(logging.INFO)        

log_endpoint_uri = str(environ["LOGS_URI"]).strip()
log_endpoint_port = int(environ["LOGS_PORT"].strip())


# Create the handler
handler = AsynchronousLogstashHandler(
    host=log_endpoint_uri,
    port=log_endpoint_port, 
    ssl_enable=True, 
    ssl_verify=False,
    database_path='')

# Here you can specify additional formatting on your log record/message
formatter = LogstashFormatter()
handler.setFormatter(formatter)

# Assign handler to the logger
logger.addHandler(handler)

# -------------------------------------------
# Healthcheck functions
# -------------------------------------------
health = HealthCheck()
BREAKER = False

def breaker_check():
    global BREAKER
    return not BREAKER, "broken"


def db_connection_check():
    global db
    db.session.execute('SELECT * FROM users')
    return True, "db ok"


def log_connection_check():
    global logger
    return True, "logger ok"


health.add_check(breaker_check)
health.add_check(db_connection_check)
health.add_check(log_connection_check)
app.add_url_rule(route + "/health/ready", route + "health/ready", view_func=lambda: health.run())
app.add_url_rule(route + "/health/live", route + "health/live", view_func=lambda: health.run())

# -------------------------------------------
# Models
# -------------------------------------------
class User(db.Model):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String)
    password_hash = db.Column(db.String)
    n_followers = db.Column(db.Integer)
    n_following = db.Column(db.Integer)
    created_on = db.Column(db.String)

    def __init__(self, email, password):
        self.email = email
        self.password_hash = self.create_pwd_hash(password)
        self.created_on = str(datetime.datetime.utcnow())
        self.n_followers = 0
        self.n_following = 0

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
                'n_followers': self.n_followers,
                'n_following': self.n_following,
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

# -------------------------------------------
# Views
# -------------------------------------------
@app.route(route + '/register', methods=['POST'])
def add_user():
    """
    This method registers new user and returns authentication token. If the users alredy exists it returns an error.
    :post_data: json {'email', 'password'}
    :return: json {'token'}}
    """
    email = request.json['email']
    password = request.json['password']

    user = User.query.filter_by(email=email).first()
    if user is not None:
        # User already exists
        return make_response({'msg': 'User already exists.'})

    # Create new user
    user = User(email, password)
    db.session.add(user)
    db.session.commit()

    token = user.authenticate(password)
    logger.info("[users-api] created new user")

    return make_response({'msg': 'Created new user.', 'token': token})


@app.route(route + '/user', methods=['POST'])
def login_user():
    """
    This method logs in an existing user.
    :return: json {'auth_token'}
    """
    _, data = consul_env.kv.get('maintenance', index=None)
    if int(data['Value'].decode('utf8')):
        return make_response({'msg': "We are sorry, we are currently working on our site and it's temporary unavailable. Check again later!"})

    email = request.json['email']
    password = request.json['password']

    user = User.query.filter_by(email=email).first()
    if user is None:
        # User does not exist
        return make_response({'msg': 'User does not exist.'})

    token = user.authenticate(password)
    if token is None:
        logger.info("[users-api] wrong password")
        # wrong password
        return make_response({'msg': 'Password is incorrect.'})

    logger.info("[users-api] logged in user")
    return make_response({'msg': 'Login successful', 'token': token})


@app.route(route + '/user/<int:user_id>', methods=['GET'])
def user_info(user_id):
    request_id = None
    if 'X-Request-ID' in request.headers:
        request_id = request.headers.get('X-Request-ID')
    user = User.query.filter_by(user_id=user_id).first()
    if user is None:
        return make_response({'msg': 'User does not exist!'})
    logger.info("[users-api][{}] user info".format(request_id))
    return make_response(user.to_dict())


@app.route(route + '/user/check', methods=['GET'])
def check_token():
    token = request.headers.get('Authorization')
    request_id = None
    if 'X-Request-ID' in request.headers:
        request_id = request.headers.get('X-Request-ID')

    # checks if token is ok
    token = request.headers.get('Authorization')
    user_id = User.decode_token(token)
    logger.info("[users-api][{}] authorization token check".format(request_id))
    return make_response({'msg': 'ok', 'user_id': user_id})


@app.route(route + '/follow', methods=['GET'])
def get_relations():
    """
    Returns users followers and following.
    :return: json {followers: [], following: []}
    """
    token = request.headers.get('Authorization')
    request_id = None
    if 'X-Request-ID' in request.headers:
        request_id = request.headers.get('X-Request-ID')

    login_user = User.decode_token(token)
    followers = Relations.query.filter_by(following=login_user).all()
    following = Relations.query.filter_by(follower=login_user).all()
    logger.info("[users-api][{}] get followers".format(request_id))
    return make_response({'msg': 'ok',
                        'followers': [{'user_id': x.follower} for x in followers],
                        'following':[{'user_id': x.following} for x in following]})
        


@app.route(route + '/follow/<user_id>', methods=['POST'])
def follow_user(user_id):
    token = request.headers.get('Authorization')
    login_user = User.decode_token(token)
    relation = Relations(login_user, user_id) 

    user_follower = User.query.filter_by(user_id=login_user).first()
    user_follower.n_following += 1

    user_followed = User.query.filter_by(user_id=user_id).first()
    user_followed.n_followers += 1

    db.session.add(relation)
    db.session.commit()
    logger.info("[users-api] someone has a new follower")
    return make_response({'msg': 'ok'})


@app.route(route + '/follow/<user_id>', methods=['DELETE'])
def unfollow_user(user_id):
    token = request.headers.get('Authorization')
    login_user = User.decode_token(token)
    db.session.query(Relations).filter(Relations.follower==login_user).filter(Relations.following==user_id).delete()
    
    user_follower = User.query.filter_by(user_id=login_user).first()
    user_follower.n_following -= 1

    user_followed = User.query.filter_by(user_id=user_id).first()
    user_followed.n_followers -= 1
    
    db.session.commit()
    logger.info("[users-api] someone just lost a follower")
    return make_response({'msg': 'ok'})

@app.route(route + '/break/please', methods=['GET'])
def breaker():
    global BREAKER
    BREAKER = True
    logger.info("[users-api] GONNA BREAK IT")
    return make_response({'msg': "I broke it :'("})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port='8080')

