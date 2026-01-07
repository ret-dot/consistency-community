from flask import Flask, render_template, request, jsonify, redirect, url_for,session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import date, datetime
from flask_migrate import Migrate
from flask_login import login_required
from flask import flash
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room

import os
from ai_engine import ai_engine # Import the AI engine

app = Flask(__name__)
socketio = SocketIO(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///calendar.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

app.general_room_initialized = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    is_private = db.Column(db.Boolean, default=False)  # NEW
    rules = db.Column(db.Text, nullable=True)  # Optional, for room rules later
    password_hash = db.Column(db.String(255))
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)


class Completion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'))
    day = db.Column(db.Date, nullable=False)


class Reward(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_reward_user_id'), nullable=False)  
    required_days = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref='created_rewards')


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='messages')
    drawing_id = db.Column(db.Integer, db.ForeignKey('drawing.id'), nullable=True)
    drawing = db.relationship('Drawing')

    @property
    def drawing_url(self):
        return self.drawing.image_data if self.drawing else None

class Drawing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=True)
    image_data = db.Column(db.Text, nullable=False) # Base64
    is_posted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='drawings')
    room = db.relationship('Room', backref='drawings')

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_requests')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_requests')



class PrivateChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    author = db.relationship('User', backref='blog_posts')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ROUTES
@app.route('/')
@login_required
def index():
    # Check if the "General" room exists
    general_room = Room.query.filter_by(name="General").first()
    
    if not general_room:
        # Create the "General" room if it doesn't exist
        general_room = Room(name="General", is_private=False)
        db.session.add(general_room)
        db.session.commit()
    
    # Add the user to the "General" room (if not already a member)
    if not Completion.query.filter_by(user_id=current_user.id, room_id=general_room.id).first():
        today = date.today()
        new_completion = Completion(user_id=current_user.id, room_id=general_room.id, day=today)
        db.session.add(new_completion)
        db.session.commit()

    # Get other rooms that the user can access
    rooms = Room.query.all()
    completions = Completion.query.filter_by(user_id=current_user.id).all()
    completed_days = [c.day.isoformat() for c in completions]
    return render_template('index.html', rooms=rooms, completed_days=completed_days, now=datetime.now())



@app.route('/room/<int:room_id>', methods=['GET', 'POST'])
@login_required
def room_view(room_id):
    room = Room.query.get_or_404(room_id)
    
    # Handle private room authentication FIRST
    if room.is_private:
        if f'room_{room.id}_auth' not in session:
            if request.method == 'POST':
                input_password = request.form.get("password")
                if not room.password_hash or not room.check_password(input_password):
                    flash("Incorrect password.", "danger")
                    return render_template('room_password.html', room=room, error="Incorrect password.")
                # Authentication successful
                session[f'room_{room.id}_auth'] = True
                # Continue to render the room
            else:
                # Show password form on GET request
                return render_template('room_password.html', room=room, error=None)
    
    # Show rules only once on GET request
    if request.method == 'GET' and room.rules:
        flash(f"Room Rules: {room.rules}", "info")
    
    # Get user's completions for THIS room only
    user_completions = Completion.query.filter_by(
        user_id=current_user.id, 
        room_id=room.id
    ).all()
    
    completed_days = [c.day.isoformat() for c in user_completions]
    today = datetime.today()
    
    # Get rewards for this room created by current user
    rewards = Reward.query.filter_by(
        room_id=room.id, 
        user_id=current_user.id
    ).all()
    
    # Get chat messages for this room
    messages = ChatMessage.query.filter_by(
        room_id=room.id
    ).order_by(ChatMessage.timestamp.asc()).all()

    return render_template('room.html',
                           room=room,
                           completed_days=completed_days,
                           today=today,
                           rewards=rewards,
                           room_id=room.id,
                           messages=messages)

@socketio.on('join_room_chat')
@login_required
def handle_join_room_chat(data):
    room_id = data['room_id']
    join_room(f'room_{room_id}')

@socketio.on('send_room_message')
@login_required
def handle_send_room_message(data):
    room_id = data['room_id']
    content = data['message']
    
    # Check for AI Command (Private)
    if content.strip().startswith('@AI'):
        # 1. Echo user's message back ONLY to the user (Private echo)
        emit('receive_room_message', {
            'username': current_user.username,
            'message': content,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'is_private': True
        }, room=request.sid) # Send to specific socket ID of sender

        # 2. Start background task for AI generation
        def generate_and_reply(user_prompt, sid):
            response = ai_engine.generate(user_prompt)
            socketio.emit('receive_room_message', {
                'username': 'AI',
                'message': response,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'is_private': True,
                'is_ai': True
            }, room=sid)
        
        # Strip '@AI' and pass prompt
        prompt = content[3:].strip()
        socketio.start_background_task(generate_and_reply, prompt, request.sid)
        return

    # Normal Public Message
    # Save to DB
    message = ChatMessage(room_id=room_id, user_id=current_user.id, content=content)
    db.session.add(message)
    db.session.commit()
    emit('receive_room_message', {
        'username': current_user.username,
        'message': content,
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M')
    }, room=f'room_{room_id}')


@app.route('/calendar/<int:room_id>/<int:year>/<int:month>')
@login_required
def calendar_view(room_id, year, month):
    completions = Completion.query.filter_by(user_id=current_user.id, room_id=room_id).all()
    completed_days = [c.day.isoformat() for c in completions if c.day.month == month and c.day.year == year]
    return jsonify(completed_days)


@app.route('/toggle_day', methods=['POST'])
@login_required
def toggle_day():
    data = request.json
    day = date.fromisoformat(data['day'])
    room_id = data['room_id']

    existing = Completion.query.filter_by(user_id=current_user.id, day=day, room_id=room_id).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        return jsonify({'status': 'removed'})
    else:
        # Ensure only one day per day per user per room
        today = date.today()
        already_done = Completion.query.filter_by(user_id=current_user.id, day=today, room_id=room_id).first()
        if already_done:
            return jsonify({'status': 'already_marked'})
        new_completion = Completion(user_id=current_user.id, day=day, room_id=room_id)
        db.session.add(new_completion)
        db.session.commit()
        return jsonify({'status': 'added'})




@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already taken.", 400

        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()

        # Ensure the General room exists
        general = Room.query.filter_by(name="General").first()
        if not general:
            general = Room(name="General", is_private=False, rules="Welcome to the General Room!")
            db.session.add(general)
            db.session.commit()

        # Add the user to the General room for today
        today = date.today()
        already_added = Completion.query.filter_by(user_id=user.id, room_id=general.id, day=today).first()
        if not already_added:
            completion = Completion(user_id=user.id, room_id=general.id, day=today)
            db.session.add(completion)
            db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/create_room', methods=['GET', 'POST'])
@login_required
def create_room():
    if request.method == 'POST':
        name = request.form.get('name')
        is_private = 'is_private' in request.form  # checkbox
        password = request.form.get('password')
        rules = request.form.get('rules')
        room = Room(name=name, is_private=is_private,rules=rules)

        if is_private and password:
            room.password_hash = generate_password_hash(password)

        db.session.add(room)
        db.session.commit()
        flash('Room created successfully!', 'success')
        
        today = date.today()
        completion = Completion(user_id=current_user.id, room_id=room.id, day=today)
        db.session.add(completion)
        db.session.commit()
        return redirect(url_for('explore_rooms'))
    return redirect(url_for('index'))
    return render_template('create_room.html')

@app.route('/explore')
@login_required
def explore_rooms():
    rooms = Room.query.all()
    room_data = []
    for room in rooms:
        # Count unique users for this room
        completion_count = db.session.query(Completion.user_id).filter_by(room_id=room.id).distinct().count()
        room_data.append({
            'room': room,
            'members': completion_count
        })
    return render_template('explore.html', rooms=room_data, now=datetime.now())


@app.route('/add_reward/<int:room_id>', methods=['POST'])
@login_required
def add_reward(room_id):
    title = request.form['title']
    description = request.form.get('description')
    required_days = int(request.form['required_days'])
    reward = Reward(
        room_id=room_id,
        user_id=current_user.id,  # NEW
        title=title,
        description=description,
        required_days=required_days
    )
    db.session.add(reward)
    db.session.commit()
    return redirect(url_for('room_view', room_id=room_id))

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    today = date.today()

    completions = Completion.query.filter_by(user_id=current_user.id).all()

    joined_room_ids = list(set(c.room_id for c in completions))
    rooms_joined_count = len(joined_room_ids)

    # Total streak days = total number of unique days completed
    all_days = set(c.day for c in completions)
    total_streak_days = len(all_days)

    # Current month streak (consistency calendar)
    current_month_days = [c.day for c in completions if c.day.year == today.year and c.day.month == today.month]

    return render_template('profile.html',
                           username=current_user.username,
                           rooms_joined=rooms_joined_count,
                           total_streak_days=total_streak_days,
                           current_month_days=[d.isoformat() for d in current_month_days],
                           today=today)
                               
@app.route('/send_friend_request/<int:user_id>', methods=['GET', 'POST'])
@login_required
def send_friend_request(user_id):
    if user_id == current_user.id:
        flash("You can't send a friend request to yourself!", "warning")
        return redirect(url_for('profile'))

    existing = FriendRequest.query.filter_by(sender_id=current_user.id, receiver_id=user_id).first()
    if existing:
        flash("Friend request already sent!", "warning")
    else:
        request_obj = FriendRequest(sender_id=current_user.id, receiver_id=user_id)
        db.session.add(request_obj)
        db.session.commit()
        flash("Friend request sent!", "success")
    return redirect(url_for('profile'))


@app.route('/friend_requests')
@login_required
def friend_requests():
    received = FriendRequest.query.filter_by(receiver_id=current_user.id, status='pending').all()
    return render_template('friend_requests.html', requests=received)


@app.route('/accept_friend/<int:request_id>')
@login_required
def accept_friend(request_id):
    req = FriendRequest.query.get_or_404(request_id)
    if req.receiver_id != current_user.id:
        return "Unauthorized", 403
    req.status = 'accepted'
    db.session.commit()
    flash("Friend request accepted!", "success")
    return redirect(url_for('friend_requests'))


@app.route('/reject_friend/<int:request_id>')
@login_required
def reject_friend(request_id):
    req = FriendRequest.query.get_or_404(request_id)
    if req.receiver_id != current_user.id:
        return "Unauthorized", 403
    req.status = 'rejected'
    db.session.commit()
    flash("Friend request rejected.", "danger")
    return redirect(url_for('friend_requests'))


@socketio.on('join_private')
@login_required
def handle_join_private(data):
    friend_id = data['friend_id']
    room_name = f'private_{min(current_user.id, friend_id)}_{max(current_user.id, friend_id)}'
    join_room(room_name)

@socketio.on('send_private_message')
@login_required
def handle_send_private_message(data):
    friend_id = data['friend_id']
    content = data['message']
    msg = PrivateChatMessage(sender_id=current_user.id, receiver_id=friend_id, content=content)
    db.session.add(msg)
    db.session.commit()
    room_name = f'private_{min(current_user.id, friend_id)}_{max(current_user.id, friend_id)}'
    emit('receive_private_message', {
        'username': current_user.username,
        'message': content,
        'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M')
    }, room=room_name)

@app.route('/drawing')
@login_required
def drawing():
    return render_template('drawing.html', mode='solo')

@app.route('/drawing/room/<int:room_id>')
@login_required
def drawing_room(room_id):
    room = Room.query.get_or_404(room_id)
    return render_template('drawing.html', mode='room', room=room)

@app.route('/drawing/friend/<int:friend_id>')
@login_required
def drawing_friend(friend_id):
    friend = User.query.get_or_404(friend_id)
    return render_template('drawing.html', mode='friend', friend=friend)

@app.route('/save_drawing', methods=['POST'])
@login_required
def save_drawing():
    data = request.json
    image_data = data['image']
    room_id = data.get('room_id')
    is_posted = data.get('is_posted', False)
    
    drawing = Drawing(
        user_id=current_user.id,
        room_id=room_id,
        image_data=image_data,
        is_posted=is_posted
    )
    db.session.add(drawing)
    db.session.commit()
    
    if room_id:
        # Auto-post to room chat if saved in a room context
        msg = ChatMessage(room_id=room_id, user_id=current_user.id, content="Shared a drawing", drawing_id=drawing.id)
        db.session.add(msg)
        db.session.commit()
        emit('receive_room_message', {
            'username': current_user.username,
            'message': 'Shared a drawing',
            'drawing_url': image_data, # Send base64 directly for immediate view
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M')
        }, room=f'room_{room_id}', namespace='/')

    return jsonify({'status': 'success', 'id': drawing.id})

# --- SocketIO Drawing Handling ---
@socketio.on('join_draw')
@login_required
def handle_join_draw(data):
    mode = data['mode']
    if mode == 'room':
        room_name = f"draw_room_{data['id']}"
    elif mode == 'friend':
        friend_id = data['id']
        room_name = f"draw_private_{min(current_user.id, friend_id)}_{max(current_user.id, friend_id)}"
    else:
        return
    join_room(room_name)
    emit('draw_ready', {'message': 'Connected to whiteboard'}, room=room_name)

@socketio.on('draw_stroke')
@login_required
def handle_draw_stroke(data):
    mode = data['mode']
    if mode == 'room':
        room_name = f"draw_room_{data['id']}"
    elif mode == 'friend':
        friend_id = data['id']
        room_name = f"draw_private_{min(current_user.id, friend_id)}_{max(current_user.id, friend_id)}"
    else:
        return
    # Broadcast to others in the room
    emit('draw_stroke', data, room=room_name, include_self=False)

@socketio.on('clear_canvas')
@login_required
def handle_clear_canvas(data):
    mode = data['mode']
    if mode == 'room':
        room_name = f"draw_room_{data['id']}"
    elif mode == 'friend':
        friend_id = data['id']
        room_name = f"draw_private_{min(current_user.id, friend_id)}_{max(current_user.id, friend_id)}"
    else:
        return
    emit('clear_canvas', {}, room=room_name, include_self=False)

@app.route('/friends', methods=['GET', 'POST'])
@login_required
def friends_dashboard():
    search_query = request.args.get('search', '')

    # Get list of current friends
    accepted_sent = FriendRequest.query.filter_by(sender_id=current_user.id, status='accepted').all()
    accepted_received = FriendRequest.query.filter_by(receiver_id=current_user.id, status='accepted').all()

    friend_ids = set()
    for fr in accepted_sent:
        friend_ids.add(fr.receiver_id)
    for fr in accepted_received:
        friend_ids.add(fr.sender_id)

    friends = User.query.filter(User.id.in_(friend_ids)).all()

    # Exclude self, existing friends, and pending requests from search
    pending_sent = FriendRequest.query.filter_by(sender_id=current_user.id, status='pending').all()
    pending_received = FriendRequest.query.filter_by(receiver_id=current_user.id, status='pending').all()
    pending_ids = {fr.receiver_id for fr in pending_sent} | {fr.sender_id for fr in pending_received}
    excluded_ids = friend_ids | pending_ids | {current_user.id}

    # Perform search if query is entered
    users = []
    if search_query:
        users = User.query.filter(User.username.contains(search_query), ~User.id.in_(excluded_ids)).all()

    return render_template('friends_dashboard.html', friends=friends, users=users, search_query=search_query)

@app.route('/art_feed')
@login_required
def art_feed():
    # Get drawings from friends
    friends = get_friends(current_user.id)
    friend_ids = [f.id for f in friends] + [current_user.id]
    drawings = Drawing.query.filter(Drawing.user_id.in_(friend_ids), Drawing.is_posted==True).order_by(Drawing.created_at.desc()).all()
    return render_template('art_feed.html', drawings=drawings)

@app.route('/focus')
@login_required
def focus_setup():
    # Pass rooms for group selection
    joined_completions = Completion.query.filter_by(user_id=current_user.id).all()
    room_ids = set(c.room_id for c in joined_completions)
    rooms = Room.query.filter(Room.id.in_(room_ids)).all()
    return render_template('focus_setup.html', rooms=rooms)

@app.route('/focus/session')
@login_required
def focus_session():
    return render_template('focus_session.html')

# --- Focus Mode Socket Events ---
@socketio.on('join_focus_room')
@login_required
def handle_join_focus(data):
    room_id = data.get('room_id')
    if room_id:
        room_name = f"focus_room_{room_id}"
        join_room(room_name)
        emit('focus_joined', {'message': f'{current_user.username} joined focus.'}, room=room_name)

@socketio.on('start_group_timer')
@login_required
def handle_start_group_timer(data):
    room_id = data.get('room_id')
    duration = data.get('duration')
    target_url = data.get('target_url')
    
    if room_id:
        room_name = f"focus_room_{room_id}"
        # Broadcast start command to everyone in the focus room
        emit('group_timer_start', {
            'duration': duration,
            'target_url': target_url,
            'started_by': current_user.username,
            'start_time': datetime.now().isoformat()
        }, room=room_name)

@app.before_request
def create_general_room():
    if not app.general_room_initialized:
        general_room = Room.query.filter_by(name='General').first()
        if not general_room:
            room = Room(name='General', is_private=False, rules='Welcome to the General Room!')
            db.session.add(room)
            db.session.commit()
        app.general_room_initialized = True


@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.route('/private_chat/<int:friend_id>')
@login_required
def private_chat(friend_id):
    friend = User.query.get_or_404(friend_id)
    messages = PrivateChatMessage.query.filter(
        ((PrivateChatMessage.sender_id == current_user.id) & (PrivateChatMessage.receiver_id == friend_id)) |
        ((PrivateChatMessage.sender_id == friend_id) & (PrivateChatMessage.receiver_id == current_user.id))
    ).order_by(PrivateChatMessage.timestamp.asc()).all()
    return render_template('private_chat.html', friend=friend, messages=messages)

def get_friends(user_id):
    sent = FriendRequest.query.filter_by(sender_id=user_id, status='accepted').all()
    received = FriendRequest.query.filter_by(receiver_id=user_id, status='accepted').all()
    friend_ids = [fr.receiver_id for fr in sent] + [fr.sender_id for fr in received]
    return User.query.filter(User.id.in_(friend_ids)).all()

@app.route('/blog')
@login_required
def blog_list():
    # Show only blogs by friends (and self)
    friends = get_friends(current_user.id)
    friend_ids = [f.id for f in friends] + [current_user.id]
    posts = BlogPost.query.filter(BlogPost.author_id.in_(friend_ids)).order_by(BlogPost.timestamp.desc()).all()
    return render_template('blog_list.html', posts=posts)

@app.route('/blog/new', methods=['GET', 'POST'])
@login_required
def blog_create():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        post = BlogPost(author_id=current_user.id, title=title, content=content)
        db.session.add(post)
        db.session.commit()
        flash('Blog post created!', 'success')
        return redirect(url_for('blog_list'))
    return render_template('blog_create.html')

@app.route('/blog/<int:post_id>')
@login_required
def blog_detail(post_id):
    post = BlogPost.query.get_or_404(post_id)
    # Only allow friends or self to view
    if post.author_id != current_user.id:
        friends = get_friends(current_user.id)
        if post.author_id not in [f.id for f in friends]:
            flash("You are not allowed to view this blog post.", "danger")
            return redirect(url_for('blog_list'))
    return render_template('blog_detail.html', post=post)

# --- YouTube Watch Together Events ---
@socketio.on('change_video')
@login_required
def handle_change_video(data):
    room_id = data.get('room_id')
    video_id = data.get('video_id')
    if room_id and video_id:
        emit('video_changed', {
            'video_id': video_id,
            'changed_by': current_user.username
        }, room=f'room_{room_id}', include_self=False)

@socketio.on('sync_video')
@login_required
def handle_sync_video(data):
    room_id = data.get('room_id')
    action = data.get('action')  # 'play', 'pause', 'seek'
    current_time = data.get('current_time', 0)
    if room_id:
        emit('video_sync', {
            'action': action,
            'current_time': current_time,
            'synced_by': current_user.username
        }, room=f'room_{room_id}', include_self=False)


# --- WebRTC Voice/Video Signaling Events ---
voice_participants = {}  # room_id -> set of user_ids

@socketio.on('join_voice')
@login_required
def handle_join_voice(data):
    room_id = data.get('room_id')
    if not room_id:
        return
    
    room_key = f'voice_{room_id}'
    if room_key not in voice_participants:
        voice_participants[room_key] = {}
    
    # Store user info with their socket id
    voice_participants[room_key][current_user.id] = {
        'username': current_user.username,
        'sid': request.sid
    }
    
    join_room(room_key)
    
    # Notify others in the voice channel that a new user joined
    emit('user_joined_voice', {
        'user_id': current_user.id,
        'username': current_user.username,
        'participants': list(voice_participants[room_key].keys())
    }, room=room_key)

@socketio.on('voice_signal')
@login_required
def handle_voice_signal(data):
    room_id = data.get('room_id')
    target_user_id = data.get('target_user_id')
    signal = data.get('signal')
    
    room_key = f'voice_{room_id}'
    if room_key in voice_participants and target_user_id in voice_participants[room_key]:
        target_sid = voice_participants[room_key][target_user_id]['sid']
        emit('voice_signal', {
            'from_user_id': current_user.id,
            'from_username': current_user.username,
            'signal': signal
        }, room=target_sid)

@socketio.on('leave_voice')
@login_required
def handle_leave_voice(data):
    room_id = data.get('room_id')
    room_key = f'voice_{room_id}'
    
    if room_key in voice_participants and current_user.id in voice_participants[room_key]:
        del voice_participants[room_key][current_user.id]
        
        emit('user_left_voice', {
            'user_id': current_user.id,
            'username': current_user.username
        }, room=room_key)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))