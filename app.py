# app.py
import os
import json
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import secrets # For generating secure tokens
import datetime # For token expiry
from flask_moment import Moment
from flask_cors import CORS
from flask_socketio import SocketIO,emit
from backend.sbom_processor import  perform_full_sbom_analysis
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:5173"])  

ALLOWED_EXTENSIONS = {
    'zip_project': {'zip'},
    'dependency_file': {'txt', 'json', 'yml', 'yaml', 'lock', 'xml', 'mod', 'gradle', 'pom'},
    'docker_tar': {'tar'},
    'existing_sbom_json': {'json', 'xml'}
}

def allowed_file(filename, upload_type):
    if upload_type not in ALLOWED_EXTENSIONS:
        return False
    file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return file_ext in ALLOWED_EXTENSIONS[upload_type]
upload_folder = "uploads"

if not os.path.exists(upload_folder):
    os.makedirs(upload_folder)
app.config['UPLOAD_FOLDER'] = upload_folder

executor = ThreadPoolExecutor(max_workers=1) 

app.config['SECRET_KEY'] = 'your_super_secret_key_here_replace_me_in_prod'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

moment = Moment(app)
socket = SocketIO(app, cors_allowed_origins="*",async_mode='eventlet',ping_interval=60,ping_timeout=120)  

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    #Personal Access Token (PAT)
    personal_access_token = db.Column(db.String(256), unique=True, nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)

    vscode_connected = db.Column(db.Boolean, default=False, nullable=False)
    vscode_last_connected = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_pat(self):
        """Generates a new, secure Personal Access Token for the user."""
        self.personal_access_token = secrets.token_urlsafe(64) # 64 bytes = ~86 characters
        self.token_expiry = datetime.datetime.now() + datetime.timedelta(days=30) # Token valid for 30 days
        db.session.add(self)
        db.session.commit()
        return self.personal_access_token

    def is_pat_valid(self):
        """Checks if the stored PAT is valid (exists and not expired)."""
        return self.personal_access_token and \
               self.token_expiry and \
               self.token_expiry > datetime.datetime.now()

    def __repr__(self):
        return f'<User {self.username}>'

class SBOM(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
    project_name = db.Column(db.String(255), nullable=True)
    sbom_type = db.Column(db.String(50), nullable=True)
    raw_sbom_json = db.Column(db.JSON, nullable=False)
    
    components_for_table = db.Column(db.JSON, nullable=True)
    license_chart_data = db.Column(db.JSON, nullable=True)
    vulnerability_chart_data = db.Column(db.JSON, nullable=True)
    dependency_chart_data = db.Column(db.JSON, nullable=True)

    def __repr__(self):
        return f'<SBOM {self.id} for User {self.user_id} - {self.project_name}>'
# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('base.html', title='Home')
    # return redirect("http://localhost:5173/")

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if current_user.is_authenticated:
#         # return redirect(url_for('dashboard'))
#          return jsonify({"success": True, "message": "Already logged in"}), 200

#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')
#         remember = True if request.form.get('remember') else False

#         user = User.query.filter_by(username=username).first()

#         if not user or not user.check_password(password):
#             # flash('Please check your login details and try again.', 'danger')
#             # return redirect(url_for('login'))
#                 return jsonify({"success": False, "message": "Invalid username or password"}), 401

#         login_user(user, remember=remember)
#         # flash('Logged in successfully!', 'success')
#         # return redirect(url_for('dashboard'))
#         return jsonify({
#     "success": True,
#     "message": "Login successful",
#     "user_id": user.id
# }), 200
        
#         response.status_code = 200
#     return response

#     # return render_template('login.html', title='Login')

@app.route('/login', methods=['POST'])
def login():
    if current_user.is_authenticated:
        return jsonify({
            "success": True,
            "message": "Already logged in",
            "user_id": current_user.id
        }), 200

    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({
            "success": False,
            "message": "Invalid username or password"
        }), 401

    login_user(user, remember=remember)

    return jsonify({
        "success": True,
        "message": "Login successful",
        "user_id": user.id
    }), 200


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        user = User.query.filter_by(username=username).first() # Check if user already exists

        if user:
            flash('Username already exists. Please choose a different one.', 'warning')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))

        if len(password) < 6: # Basic password length validation
            flash('Password must be at least 6 characters long.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password) # Hash the password

        db.session.add(new_user)
        db.session.commit() # Commit the new user first

        new_user.generate_pat() # This will commit the new token to the DB

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    # return render_template('register.html', title='Register')
    return redirect("http://localhost:5173/login")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    # flash('You have been logged out.', 'info')
    # return redirect(url_for('home'))
    return jsonify({"success": True, "message": "Logged out successfully"}), 200

@app.route('/dashboard')
@login_required
def dashboard():
    # --- IMPORTANT FIX: Refresh current_user to ensure latest PAT data ---
    user_from_db = User.query.get(current_user.id)
    user_id = user_from_db.id
    # return render_template('dashboard.html', title='Dashboard', user=user_from_db)
    return redirect(f"http://localhost:5173/sidebar?user_id={user_id}")

# --- API Endpoint for Token Validation ---
@app.route('/api/user_info', methods=['GET'])
def api_user_info():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Authorization header missing"}), 401

    try:
        token_type, token = auth_header.split(' ', 1)
        if token_type.lower() != 'bearer':
            return jsonify({"message": "Invalid token type, must be Bearer"}), 401
    except ValueError:
        return jsonify({"message": "Invalid Authorization header format"}), 401

    user = User.query.filter_by(personal_access_token=token).first()

    if not user:
        return jsonify({"message": "Invalid or unknown token"}), 401

    if not user.is_pat_valid():
        return jsonify({"message": "Token expired or invalid"}), 401

    return jsonify({
        "message": "Token valid",
        "user": {
            "id": user.id,
            "username": user.username,
            "token_expiry": user.token_expiry.isoformat() if user.token_expiry else None
        }
    }), 200


# --- API Endpoint for PAT Regeneration ---
@app.route('/api/regenerate_pat', methods=['POST'])
@login_required # Only logged-in users can regenerate their PAT
def api_regenerate_pat():
    user = User.query.filter_by(id=current_user.id).first()
    if not user:
        return jsonify({"message": "Unauthorized: Valid token required to set status to 'connected'"}), 401
    
    try:
        new_pat = current_user.generate_pat() 
        user.vscode_connected = False
        user.vscode_last_connected = datetime.datetime.now()
        db.session.commit() 
        app.logger.info("User '%s' VS Code Extension connection status updated to: Disconnected", user.username)
        socket.emit('vscode_status_update', 
                      {'status': 'disconnected', 'last_updated': user.vscode_last_connected.isoformat()}, 
                      room=str(user.id))
        db.session.refresh(current_user)
        return jsonify({
            "message": "Personal Access Token regenerated successfully!",
            "personal_access_token": new_pat,
            "token_expiry": current_user.token_expiry.isoformat()
        }), 200
    except Exception as e:
        db.session.rollback() # Rollback in case of error
        return jsonify({"message": f"Failed to regenerate PAT: {str(e)}"}), 500

# ---- Connection Status Endpoint ----  
@app.route('/api/connection_status', methods=['POST'])
def update_connection_status():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Request body missing or not JSON"}), 400

    status = data.get('status')

    if status not in ['connected', 'disconnected']:
        return jsonify({"message": "Invalid status. Must be 'connected' or 'disconnected'."}), 400

    auth_header = request.headers.get('Authorization')
    token = None
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]

    user = None
    if token:
        user = User.query.filter_by(personal_access_token=token).first()
        if user and not user.is_pat_valid():
            user = None

    if status == 'connected':
        if not user:
            return jsonify({"message": "Unauthorized: Valid token required to set status to 'connected'"}), 401
        
        user.vscode_connected = True
        user.vscode_last_connected = datetime.datetime.now()
        db.session.commit() 
        app.logger.info("User '%s' VS Code Extension connection status updated to: Connected", user.username)
        socket.emit('vscode_status_update', 
                      {'status': 'connected', 'last_updated': user.vscode_last_connected.isoformat()}, 
                      room=str(user.id))
    elif status == 'disconnected':
        if user: 
            user.vscode_connected = False
            user.vscode_last_connected = datetime.datetime.now()
            db.session.commit() 
            app.logger.info("User '%s' VS Code Extension connection status updated to: Disconnected", user.username)
            socket.emit('vscode_status_update', 
                      {'status': 'disconnected', 'last_updated': user.vscode_last_connected.isoformat()}, 
                      room=str(user.id))
        else:
            app.logger.info("VS Code Extension sent 'disconnected' status, but no valid user token provided.")

    return jsonify({"message": "Connection status updated successfully"}), 200


         
@app.route('/api/get_connection_status', methods=['GET'])
# @login_required # This ensures current_user is available
def get_connection_status():
    status = 'connected' if current_user.vscode_connected else 'disconnected'
    last_updated = current_user.vscode_last_connected.isoformat() if current_user.vscode_last_connected else None

    return jsonify({
        'status': status,
        'last_updated': last_updated
    }), 200

# ----- API Endpoint for SBOM Upload ----
@app.route('/api/upload_sbom', methods=['POST'])
@login_required
def upload_sbom():
    app.logger.info(f"Received SBOM upload request for user {current_user.username}")
    if 'sbom_file' not in request.files:
        return jsonify({"message": "No file part in the request"}), 400
    
    file = request.files['sbom_file']
    upload_type = request.form.get('upload_type')
    project_name = request.form.get('project_name', 'Unnamed Project')
    
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400

    if upload_type not in ['zip_project', 'dependency_file', 'docker_tar', 'existing_sbom_json']:
        return jsonify({"message": "Invalid upload type"}), 400
    
    if not allowed_file(file.filename, upload_type):
        return jsonify({"message": f"Invalid file type for '{upload_type}'. Expected: {', '.join(ALLOWED_EXTENSIONS[upload_type])}"}), 400

    filename = secure_filename(file.filename)     
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path) 
    
    app.logger.info(f"File '{filename}' saved to {file_path} for user {current_user.username}")
    
    socket.start_background_task(
        target=perform_full_sbom_analysis,
        file_path=file_path,
        upload_type=upload_type,
        project_name=project_name,
        user_id=current_user.id, 
        socketio_instance=socket,
        db_instance=db,          
        app_instance=app         
    )

    # Return immediate response to frontend
    return jsonify({"message": "SBOM processing started in background. Dashboard will update shortly."}), 202 # 202 Accepted

# ---- API for VScode Extension to fetch SBOM data ----
@app.route('/api/upload_sbom_from_extension', methods=['POST'])
def upload_sbom_from_extension():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Authorization header missing"}), 401

    try:
        token_type, token = auth_header.split(' ', 1)
        if token_type.lower() != 'bearer':
            return jsonify({"message": "Invalid token type, must be Bearer"}), 401
    except ValueError:
        return jsonify({"message": "Invalid Authorization header format"}), 401

    user = User.query.filter_by(personal_access_token=token).first()

    if not user or not user.is_pat_valid():
        return jsonify({"message": "Invalid or expired Personal Access Token"}), 401

    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400
    
    raw_sbom_json = request.get_json()
    project_name = request.args.get('project_name', 'Unnamed Project (Extension)') 
    # You might want to get a commit_hash from headers or query params too for VCS linking
    # commit_hash = request.args.get('commit_hash') 

    if not raw_sbom_json:
        return jsonify({"message": "No SBOM JSON provided in request body"}), 400

    if isinstance(raw_sbom_json, dict) and 'sbomJson' in raw_sbom_json and isinstance(raw_sbom_json['sbomJson'], dict):
        app.logger.info("Unwrapping SBOM from 'sbomJson' key.")
        raw_sbom_json = raw_sbom_json['sbomJson']
    app.logger.info(f"Received SBOM JSON from extension for user {user.username}, project '{project_name}'.")

    temp_dir = 'uploads' 
    os.makedirs(temp_dir, exist_ok=True)
    temp_filename = f"sbom_extension_{user.id}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
    filepath = os.path.join(temp_dir, temp_filename)
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(raw_sbom_json, f, indent=2)
        app.logger.info(f"SBOM JSON from extension saved temporarily to: {filepath}")

        socket.start_background_task(
            target=perform_full_sbom_analysis,
            file_path=filepath, # Pass the temporary file path
            upload_type='existing_sbom_json', # Treat as existing SBOM JSON
            project_name=project_name,
            user_id=user.id, 
            socketio_instance=socket, 
            db_instance=db,             
            app_instance=app            
        )
        return jsonify({"message": "SBOM processing initiated successfully from extension!"}), 202
    except Exception as e:
        app.logger.error(f"Error processing SBOM from extension: {e}")
        return jsonify({"message": f"Server error during SBOM processing: {str(e)}"}), 500
    finally:
        # The finally block in perform_full_sbom_analysis will handle cleanup of this temp file
        pass

        
# ---- Update Dashboard with New SBOM Data ----
@app.route('/api/get_latest_sbom_data', methods=['GET'])
# @login_required
def get_latest_sbom_data():
    latest_sbom = SBOM.query.filter_by(user_id=current_user.id).order_by(SBOM.timestamp.desc()).first()
    if latest_sbom:
        return jsonify({
            "components": latest_sbom.components_for_table,
            "license_chart": latest_sbom.license_chart_data,
            "project_name": latest_sbom.project_name,
            "sbom_timestamp": latest_sbom.timestamp.isoformat(),
            "vulnerability_chart": latest_sbom.vulnerability_chart_data,
            "dependency_chart": latest_sbom.dependency_chart_data
        }), 200
    return jsonify({
        "components": [],
        "license_chart": {"labels": [], "data": []},
        "project_name": "No SBOM Data",
        "sbom_timestamp": None,
        "vulnerability_chart": {"labels": ['Critical', 'High', 'Medium', 'Low', 'None'], "data": [0, 0, 0, 0, 0]},
        "dependency_chart": {"labels": ['Depth 1', 'Depth 2', 'Depth 3', 'Depth 4+'], "data": [0, 0, 0, 0]},
        "message": "No SBOMs found for this user."
    }), 200
    
@socket.on('connect')
def handle_connect():
    print(f"Socket.IO client connected. SID: {request.sid}")

@socket.on('disconnect')
def handle_disconnect():
    print(f"Socket.IO client disconnected. SID: {request.sid}")

@socket.on('join_user_room')
@login_required
def on_join_user_room(data):
    user_id = data.get('user_id')
    if user_id and str(user_id) == str(current_user.id):
        from flask_socketio import join_room
        join_room(str(user_id))
        print(f"User {current_user.username} (ID: {user_id}) joined Socket.IO room {user_id}")
    else:
        print(f"WARNING: Attempted to join room {user_id} with mismatching or missing user ID for current_user {current_user.id}")
@app.route("/sbom", methods=["GET"])
@login_required
def sbom_dasboard():
    return render_template('sbom_dasboard.html',user_id=current_user.id,title='SBOM Dashboard')


# --- Database Initialization ---
with app.app_context():
    db.create_all() # This will create the new columns if they don't exist
    
    if not User.query.filter_by(username='demo_user').first():
        demo_user = User(username='demo_user')
        demo_user.set_password('password123')
        
        demo_user.vscode_connected = False
        demo_user.vscode_last_connected = None
        
        db.session.add(demo_user) 
        db.session.commit() 

        demo_user.generate_pat() # This will commit the new token to the DB
        print(f"Demo user 'demo_user' created with password 'password123' and PAT: {demo_user.personal_access_token}")
    else:
        print("Demo user 'demo_user' already exists.")
        existing_demo_user = User.query.filter_by(username='demo_user').first()
        if not existing_demo_user.personal_access_token or not existing_demo_user.is_pat_valid():
            existing_demo_user.generate_pat()
            print(f"Generated/Refreshed PAT for existing demo user: {existing_demo_user.personal_access_token}")
        
        if existing_demo_user.vscode_connected is None: # Check if the column was just added
            existing_demo_user.vscode_connected = False
            existing_demo_user.vscode_last_connected = None
            db.session.commit()

if __name__ == '__main__':
    socket.run(app,debug=True)
