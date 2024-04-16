import os
from flask import Flask, render_template, url_for, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from flask_login import (
    UserMixin,
    LoginManager,
    login_user,
    login_required,
    logout_user,
)
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SECRET_KEY"] = "ThisKeyIsVerySecret123"
app.app_context().push()
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    finished = db.Column(db.DateTime, default=datetime.utcnow)
    sid = db.Column(db.String(50), unique=True, nullable=True)
    num_of_rounds_played = db.Column(db.Integer, default=0)
    round_win = db.Column(db.Integer, default=0)
    game_win = db.Column(db.Integer, default=0)
    round_loss = db.Column(db.Integer, default=0)
    game_loss = db.Column(db.Integer, default=0)
    round_tied = db.Column(db.Integer, default=0)
    matches = db.relationship("Match", backref="user", lazy=True)


class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    opponent_username = db.Column(db.String(25), nullable=False)
    date_of_match_start = db.Column(db.DateTime, default=datetime.utcnow)
    date_of_match_end = db.Column(db.DateTime, default=datetime.utcnow)
    result = db.Column(db.String(20), default="Game not finished")


class RegisterForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=25)],
        render_kw={"placeholder": "Username"},
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=25)],
        render_kw={"placeholder": "Password"},
    )
    register_submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That Username already exists. Please choose a different one."
            )


class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=25)],
        render_kw={"placeholder": "Username"},
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=25)],
        render_kw={"placeholder": "Password"},
    )

    login_submit = SubmitField("Log In")


# SocketIO events
@socketio.on("connect")
def handle_connect():
    user = User.query.filter_by(username=session["username"]).first()
    user.sid = request.sid
    db.session.commit()
    emit_user_list()


@socketio.on("disconnect")
def handle_disconnect():
    user = User.query.filter_by(username=session["username"]).first()
    user.sid = None
    db.session.commit()
    # print(f"{user.name} has disconnected.")
    emit_user_list()


@socketio.on("empty_previous_result")
def empty_previous_result(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    if receiver and receiver.sid:
        emit("emptying", room=receiver.sid)


@socketio.on("for_unblock")
def for_unblock(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    if receiver and receiver.sid:
        emit("unblock", room=receiver.sid)


@socketio.on("request_game")
def handle_game_request(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    if receiver and receiver.sid:
        emit("game_request", {"sender": session["username"]}, room=receiver.sid)


@socketio.on("accept_request")
def handle_accept_request(data):
    sender = User.query.filter_by(username=data["sender"]).first()
    receiver = User.query.filter_by(username=session["username"]).first()

    if sender and receiver:
        emit(
            "start_game",
            {"sender": data["sender"], "receiver": session["username"]},
            room=sender.sid,
        )
        emit(
            "start_game",
            {"sender": session["username"], "receiver": data["sender"]},
            room=receiver.sid,
        )


@socketio.on("game_choice")
def handle_game_choice(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    emit(
        "opponent_choice",
        {"sender": data["sender"], "choice": data["choice"]},
        room=receiver.sid,
    )


@socketio.on("opponent_choice")
def handle_opponent_choice(data):
    emit("opponent_choice", {"receiver": data["receiver"], "choice": data["choice"]})


@socketio.on("game_result")
def handle_game_result(data):
    emit("opponent_choice", {"receiver": data["receiver"], "choice": data["choice"]})


@socketio.on("offer_win_count")
def handle_offer_win_count(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    emit(
        "accept_win_count",
        {"win_amount": data["win_amount"]},
        room=receiver.sid,
    )


@socketio.on("add_round_played")
def add_round_played(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    receiver.num_of_rounds_played = receiver.num_of_rounds_played + 1
    db.session.commit()


@socketio.on("add_round_tied")
def add_round_tied(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    receiver.round_tied = receiver.round_tied + 1
    db.session.commit()


@socketio.on("add_round_win")
def add_round_win(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    receiver.round_win = receiver.round_win + 1
    db.session.commit()


@socketio.on("add_game_win")
def add_game_win(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    receiver.game_win = receiver.game_win + 1
    match_result = (
        Match.query.filter_by(player_id=receiver.id)
        .order_by(Match.date_of_match_start.desc())
        .first()
    )
    match_result.date_of_match_end = datetime.utcnow()
    match_result.result = "You Won!"
    db.session.commit()


@socketio.on("add_round_loss")
def add_round_loss(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    receiver.round_loss = receiver.round_loss + 1
    db.session.commit()


@socketio.on("add_game_loss")
def add_game_loss(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    receiver.game_win = receiver.game_loss + 1
    match_result = (
        Match.query.filter_by(player_id=receiver.id)
        .order_by(Match.date_of_match_start.desc())
        .first()
    )
    match_result.date_of_match_end = datetime.utcnow()
    match_result.result = "You Lost!"
    db.session.commit()


@socketio.on("accept_amount")
def handle_accept_amount(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    sender = User.query.filter_by(username=session["username"]).first()
    new_match_1 = Match(player_id=sender.id, opponent_username=receiver.username)
    db.session.add(new_match_1)
    db.session.commit()
    emit(
        "win_count_accepted",
        {"win_amount": data["win_amount"]},
        room=receiver.sid,
    )


@socketio.on("game_started")
def handle_game_started(data):
    receiver = User.query.filter_by(username=data["receiver"]).first()
    sender = User.query.filter_by(username=session["username"]).first()
    new_match_1 = Match(player_id=sender.id, opponent_username=receiver.username)
    db.session.add(new_match_1)
    db.session.commit()


@socketio.on("update_list")
def handle_update_list():
    users = User.query.filter(
        User.username != session["username"], User.sid.isnot(None)
    ).all()
    emit("user_list", {"users": [user.username for user in users]})


def emit_user_list():
    users = User.query.filter(
        User.username != session["username"], User.sid.isnot(None)
    ).all()
    emit("user_list", {"users": [user.username for user in users]})


@app.route("/")
def home():
    return redirect(url_for("log_in"))


@app.route("/log_in", methods=["GET", "POST"])
def log_in():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                session["username"] = form.username.data
                login_user(user)
                return redirect(url_for("dashboard"))
    return render_template("log_in.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    user = User.query.filter_by(username=session["username"]).first()
    user.sid = None
    db.session.commit()
    name = session["username"]
    print(f"User {name} has logged out")
    session.pop("username", None)
    logout_user()
    return redirect(url_for("log_in"))


@app.route("/game", methods=["GET", "POST"])
def game():
    sender = request.args.get("sender")
    receiver = request.args.get("receiver")
    return render_template("game.html", sender=sender, receiver=receiver)


@app.route("/player_list", methods=["GET", "POST"])
def player_list():
    if "username" not in session:
        return redirect(url_for("log_in"))
    users = User.query.filter(User.username != session["username"]).all()
    for user in users:
        print(f"{user.username}")
    return render_template(
        "player_list.html", username=session["username"], users=users
    )


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "username" not in session:
        return redirect(url_for("index"))
    user = User.query.filter_by(username=session["username"]).first()
    matches = Match.query.filter_by(player_id=user.id).all()
    return render_template("profile.html", user=user, matches=matches)


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    if "username" not in session:
        return redirect(url_for("index"))
    return render_template("dashboard.html")


@app.route("/sign_up", methods=["GET", "POST"])
def sign_up():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            password=hashed_password,
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("log_in"))

    return render_template("sign_up.html", form=form)


if __name__ == "__main__":
    if not os.path.exists("instance/database.db"):
        db.create_all()
    socketio.run(app, debug=True)
