import os
from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt
from flask_migrate import Migrate
from flask_cors import CORS
from models import db, User
from dotenv import load_dotenv
from datetime import timedelta


load_dotenv() 

app = Flask(__name__)
CORS(app)

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'app.db')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

db.init_app(app)
BLACKLIST = set()

@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    return jwt_payload['jti'] in BLACKLIST


# User Routes
@app.route('/', methods=['GET'])
def index():
    return jsonify({"message": "Welcome to the API"})


@app.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    users = User.query.all()
    user_list = []
    for user in users:
        user_list.append({
            "id": user.id,  
            "username": user.username,
            "email": user.email
            
        })
    
    return jsonify(users=user_list), 200

@app.route("/users/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    current_user_id = get_jwt_identity()  
    
    user = User.query.get(user_id)
    
    if user is None:
        return jsonify(message="User not found"), 404

    if user.id != current_user_id:
        return jsonify(message="You do not have permission to update this user"), 403

    data = request.get_json()
    
    if "username" in data:
        user.username = data["username"]
    if "email" in data:
        user.email = data["email"]
    if "password" in data:
        user.password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    
    db.session.commit()
    return jsonify(message="User updated successfully"), 200

@app.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    current_user_id = get_jwt_identity()
    
    user = User.query.get(user_id)
    
    if user is None:
        return jsonify(message="User not found"), 404

    if user.id != current_user_id:
        return jsonify(message="You do not have permission to delete this user"), 403

    db.session.delete(user)
    db.session.commit()
    return jsonify(message="User deleted successfully"), 200

@app.route("/login", methods=["POST"])
def login():
    email = request.json.get("email")
    password = request.json.get("password")

    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify(message="Invalid email or password"), 401

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(username=username, email=email, password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify(message="User created successfully"), 201

@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    BLACKLIST.add(jti)
    return jsonify(message="Successfully logged out"), 200

if __name__ == "__main__":
    app.run(debug=True)
