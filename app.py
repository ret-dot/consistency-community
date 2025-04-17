from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import date, datetime
from flask_migrate import Migrate
from flask_login import login_required
from flask import flash
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
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
    password_hash = db.Column(db.String(256))
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
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


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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
    completions = Completion.query.filter_by(user_id=current_user.id).all()
    days = set(c.day for c in completions)

    # Restrict access for non-General rooms if user doesn't have 2-day consistency
    if room.name != "General" and len(days) < 2:
        flash("You need 2 days of consistency to join this room.", "danger")
        return redirect(url_for('index'))

    # Handle private room password check
    if room.is_private:
        if request.method == 'POST':
            input_password = request.form.get("room_password")
            if not room.check_password(input_password):
                flash("Incorrect password.", "danger")
                return redirect(url_for('explore_rooms'))

    # Show rules on GET request
    if request.method == 'GET' and room.rules:
        flash(f"Room Rules: {room.rules}", "info")

    # Check room-specific consistency for non-General rooms
    if room.name != "General":
        completion_count = Completion.query.filter_by(user_id=current_user.id, room_id=room.id).count()
        if completion_count < 2:
            flash('You must have at least 2-day consistency in this room to enter.', 'danger')
            return redirect(url_for('index'))

    user_completions = [c for c in completions if c.room_id == room.id]
    completed_days = [c.day.isoformat() for c in user_completions]
    today = datetime.today()
    rewards = Reward.query.filter_by(room_id=room.id, user_id=current_user.id).all()
    messages = ChatMessage.query.filter_by(room_id=room.id).order_by(ChatMessage.timestamp.asc()).all()

    return render_template('room.html',
                           room=room,
                           completed_days=completed_days,
                           today=today,
                           rewards=rewards,
                           room_id=room.id,
                           messages=messages)



@app.route('/send_message/<int:room_id>', methods=['POST'])
@login_required
def send_message(room_id):
    content = request.form.get('message')
    if content:
        message = ChatMessage(room_id=room_id, user_id=current_user.id, content=content)
        db.session.add(message)
        db.session.commit()
    return redirect(url_for('room_view', room_id=room_id))


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
        room = Room(name=name, is_private=is_private)

        if is_private and password:
            room.password = generate_password_hash(password)

        db.session.add(room)
        db.session.commit()
        flash('Room created successfully!', 'success')
        return redirect(url_for('explore_rooms'))
    today = date.today()
    completion = Completion(user_id=current_user.id, room_id=room.id, day=today)
    db.session.add(completion)
    db.session.commit()

    return redirect(url_for('index'))
    return render_template('create_room.html')

@app.route('/explore')
@login_required
def explore_rooms():
    rooms = Room.query.all()
    room_data = []
    for room in rooms:
        completion_count = Completion.query.filter_by(room_id=room.id).distinct(Completion.user_id).count()
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

@app.route('/send_friend_request/<int:user_id>')
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


@app.route('/chat/<int:friend_id>', methods=['GET', 'POST'])
@login_required
def chat(friend_id):
    if request.method == 'POST':
        content = request.form.get('message')
        if content:
            msg = PrivateChatMessage(sender_id=current_user.id, receiver_id=friend_id, content=content)
            db.session.add(msg)
            db.session.commit()
    messages = PrivateChatMessage.query.filter(
        ((PrivateChatMessage.sender_id == current_user.id) & (PrivateChatMessage.receiver_id == friend_id)) |
        ((PrivateChatMessage.sender_id == friend_id) & (PrivateChatMessage.receiver_id == current_user.id))
    ).order_by(PrivateChatMessage.timestamp.asc()).all()
    friend = User.query.get(friend_id)
    return render_template('private_chat.html', friend=friend, messages=messages)

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


if __name__ == '__main__':
    app.run(debug=True)
