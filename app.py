from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import string, random, datetime
from bson import ObjectId
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)

app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config["MONGO_URI"] = "mongodb+srv://hanshimawan26:tcq9qTGNueeCulq1@debatecoordinated.ka2kk.mongodb.net/debatecoordinated?retryWrites=true&w=majority&appName=DebateCoordinated"
app.config["JWT_SECRET_KEY"] = "sredthfrrhergse897621"  # set your JWT secret

mongo = PyMongo(app)
jwt = JWTManager(app)

# ------------------------
# Registration Endpoint
# ------------------------
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    username = data.get('username')
    name = data.get('name')  # added field
    password = data.get('password')
    institution = data.get('institution')

    # Check uniqueness of email and username
    if mongo.db.users.find_one({"email": email}):
        return jsonify({"error": "Email already registered"}), 400
    if mongo.db.users.find_one({"username": username}):
        return jsonify({"error": "Username already taken"}), 400

    # Generate a unique user tag
    def generate_unique_tag():
        while True:
            tag = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
            if not mongo.db.users.find_one({"tag": tag}):
                return tag

    user_tag = generate_unique_tag()
    hashed_password = generate_password_hash(password)
    user = {
        "tag": user_tag,
        "email": email,
        "username": username,
        "name": name,
        "password": hashed_password,
        "regis_date": datetime.datetime.utcnow(),
        "institution": institution
    }
    result = mongo.db.users.insert_one(user)
    user['_id'] = str(result.inserted_id)
    return jsonify({"message": "User registered successfully", "user": user}), 200

# ------------------------
# Login Endpoint (JWT)
# ------------------------
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user = mongo.db.users.find_one({"email": email})
    if user and check_password_hash(user['password'], password):
        # Create an access token with the user's id as identity
        access_token = create_access_token(identity=str(user['_id']))
        return jsonify({
            "message": "Logged in successfully",
            "access_token": access_token,
            "user": {"username": user['username']}
        }), 200
    return jsonify({"error": "Invalid credentials"}), 401

# ------------------------
# Current User Endpoint (Protected)
# ------------------------
@app.route('/api/current_user', methods=['GET'])
@jwt_required()
def current_user_info():
    current_user_id = get_jwt_identity()
    user = mongo.db.users.find_one({"_id": ObjectId(current_user_id)})
    if user:
        user['_id'] = str(user['_id'])
        return jsonify({"user": user}), 200
    return jsonify({"error": "User not found"}), 404

# ------------------------
# Debate Endpoints (Protected)
# ------------------------
@app.route('/api/debate', methods=['POST'])
@jwt_required()
def create_debate():
    data = request.json
    title = data.get('title') or f"Debate on {datetime.datetime.utcnow().strftime('%Y-%m-%d')}"
    motion = data.get('motion')
    debate_format = data.get('format')
    mode = data.get('mode', '')
    teams = data.get('teams')

    # Generate a unique 8-character debate tag
    def generate_unique_debate_tag():
        while True:
            tag = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if not mongo.db.debate_sessions.find_one({"debate_tag": tag}):
                return tag

    debate_tag = generate_unique_debate_tag()
    current_user_id = get_jwt_identity()

    debate = {
        "user_id": current_user_id,
        "format": debate_format,
        "mode": mode,
        "title": title,
        "motion": motion,
        "teams": teams,  # expected structure: { government: { "GOV1": {name, time}, ... }, opposition: { ... } }
        "debate_tag": debate_tag,
        "date": datetime.datetime.utcnow(),
        "status": "ongoing"
    }
    result = mongo.db.debate_sessions.insert_one(debate)
    debate['_id'] = str(result.inserted_id)
    return jsonify({"message": "Debate created", "debate": debate}), 200

@app.route('/api/debate/<debate_id>/save_time', methods=['PUT'])
@jwt_required()
def save_time(debate_id):
    data = request.json
    speaker_key = data.get('speaker_key')  # e.g., "GOV1"
    time_val = data.get('time')             # time in seconds (or formatted string)
    team_field = "government" if speaker_key.startswith("GOV") else "opposition"
    update_query = {"$set": {f"teams.{team_field}.{speaker_key}.time": time_val}}
    mongo.db.debate_sessions.update_one({"_id": ObjectId(debate_id)}, update_query)
    return jsonify({"message": f"Time for {speaker_key} saved"}), 200

@app.route('/api/debate/<debate_id>/end', methods=['POST'])
@jwt_required()
def end_debate(debate_id):
    mongo.db.debate_sessions.update_one({"_id": ObjectId(debate_id)}, {"$set": {"status": "finished"}})
    debate = mongo.db.debate_sessions.find_one({"_id": ObjectId(debate_id)})
    debate['_id'] = str(debate['_id'])
    return jsonify({"message": "Debate ended", "debate": debate}), 200

@app.route('/api/debate/<debate_id>', methods=['GET'])
@jwt_required()
def get_debate(debate_id):
    debate = mongo.db.debate_sessions.find_one({"_id": ObjectId(debate_id)})
    if debate:
        debate['_id'] = str(debate['_id'])
        return jsonify({"debate": debate}), 200
    return jsonify({"error": "Debate not found"}), 404

@app.route('/api/debates', methods=['GET'])
@jwt_required()
def get_debates():
    current_user_id = get_jwt_identity()
    debates = list(mongo.db.debate_sessions.find({"user_id": current_user_id}))
    for debate in debates:
        debate['_id'] = str(debate['_id'])
    return jsonify({"debates": debates}), 200

@app.route('/api/debate/<debate_id>/update_stopwatch', methods=['PUT'])
@jwt_required()
def update_stopwatch():
    data = request.json
    speaker_key = data.get('speaker_key')  # e.g. "GOV1"
    action = data.get('action')            # one of "start", "stop", "reset", "save"
    team_field = "government" if speaker_key.startswith("GOV") else "opposition"
    now = datetime.datetime.utcnow()
    
    debate = mongo.db.debate_sessions.find_one({"_id": ObjectId(debate_id)})
    if not debate:
        return jsonify({"error": "Debate not found"}), 404

    # Get the current stopwatch state
    state = debate["teams"][team_field][speaker_key].get("stopwatch", {"offset": 0, "start": None, "is_running": False})
    
    if action == "start":
        if not state.get("is_running"):
            state["start"] = now.isoformat() + "Z"  # ISO string with a "Z" suffix
            state["is_running"] = True
    elif action == "stop":
        if state.get("is_running") and state.get("start"):
            start_time = datetime.datetime.fromisoformat(state["start"].replace("Z", ""))
            elapsed_ms = (now - start_time).total_seconds() * 1000
            state["offset"] = state.get("offset", 0) + elapsed_ms
            state["start"] = None
            state["is_running"] = False
    elif action == "reset":
        state = {"offset": 0, "start": None, "is_running": False}
    elif action == "save":
        # Save action finalizes the stopwatch value (similar to stop)
        if state.get("is_running") and state.get("start"):
            start_time = datetime.datetime.fromisoformat(state["start"].replace("Z", ""))
            elapsed_ms = (now - start_time).total_seconds() * 1000
            state["offset"] = state.get("offset", 0) + elapsed_ms
        state["start"] = None
        state["is_running"] = False
    else:
        return jsonify({"error": "Invalid action"}), 400

    update_query = {"$set": {f"teams.{team_field}.{speaker_key}.stopwatch": state}}
    mongo.db.debate_sessions.update_one({"_id": ObjectId(debate_id)}, update_query)
    return jsonify({"message": "Stopwatch updated", "state": state}), 200

if __name__ == '__main__':
    app.run(debug=True)