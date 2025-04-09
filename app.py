from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import date, datetime
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///calendar.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# MODELS
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)


class Completion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'))
    day = db.Column(db.Date, nullable=False)


class Reward(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    required_days = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='messages')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ROUTES
@app.route('/')
@login_required
def index():
    rooms = Room.query.all()
    completions = Completion.query.filter_by(user_id=current_user.id).all()
    completed_days = [c.day.isoformat() for c in completions]
    return render_template('index.html', rooms=rooms, completed_days=completed_days, now=datetime.now())


@app.route('/room/<int:room_id>')
@login_required
def room_view(room_id):
    room = Room.query.get_or_404(room_id)
    completions = Completion.query.filter_by(user_id=current_user.id, room_id=room_id).all()
    completed_days = [c.day.isoformat() for c in completions]
    today = datetime.today()
    rewards = Reward.query.filter_by(room_id=room_id).all()
    messages = ChatMessage.query.filter_by(room_id=room_id).order_by(ChatMessage.timestamp.asc()).all()

    return render_template('room.html', room=room, completed_days=completed_days,
                           today=today, rewards=rewards, room_id=room_id,
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


@app.route('/create_room', methods=['POST'])
@login_required
def create_room():
    name = request.form['room_name']
    room = Room(name=name)
    db.session.add(room)
    db.session.commit()

    today = date.today()
    completion = Completion(user_id=current_user.id, room_id=room.id, day=today)
    db.session.add(completion)
    db.session.commit()

    return redirect(url_for('index'))


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
    reward = Reward(room_id=room_id, title=title, description=description, required_days=required_days)
    db.session.add(reward)
    db.session.commit()
    return redirect(url_for('room_view', room_id=room_id))


if __name__ == '__main__':
    app.run(debug=True)
