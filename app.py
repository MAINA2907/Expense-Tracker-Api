import os
import random

from flask_migrate import Migrate
from flask import Flask
from flask_cors import CORS
from sqlalchemy import MetaData
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api,Resource
from flask import request, session,make_response, jsonify
from flask_bcrypt import Bcrypt
from datetime import timedelta
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, current_user
# from app import Login
from models import db


app = Flask(__name__)
app.secret_key = b'Y\xf1Xz\x00\xad|eQ\x80t \xca\x1a\x10K'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///Expensedb.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config["JWT_SECRET_KEY"] = "fsbdgfnhgvjnvhmvh"+str(random.randint(1,1000000000000)) 
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["SECRET_KEY"] = "JKSRVHJVFBSRDFV"+str(random.randint(1,1000000000000))
app.json.compact = False
CORS(app)
migrate = Migrate(app, db)
db.init_app(app)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

api = Api(app)
from config import *
from models import User,Expense, Budget, Category

class Register(Resource):
    def post(self):
        data = request.get_json()
        new_user = User(
            email = data.get("email"),
            name = data.get("name"),
            password = bcrypt.generate_password_hash(data.get("password")).decode('utf-8')
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'success':'user created successfully'})

class Login(Resource):
    def post(self):
        data = request.get_json()
        email = data['email']
        password = data['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}
        return {"error":"Invalid email or password"}, 400
    
api.add_resource(Register, '/register')
api.add_resource(Login, "/login")
    
if __name__ == "__main__":
    app.run(port=5555, debug=True)