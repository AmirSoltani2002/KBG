# app.py
from flask import Flask, render_template, redirect, url_for, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, Ticket
from forms import LoginForm, TicketForm, RegistrationForm, ForwardForm, MineForm, All, RemoveUser
from flask import flash
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tickets.db'
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index(tickets = None):
    form = TicketForm()
    form.recipient.choices = [(user.id, user.username) for user in User.query.all() if user.id != current_user.id]
    if form.validate_on_submit():
        filename = None
        if form.file.data and allowed_file(form.file.data.filename):
            filename = secure_filename(form.description.data + '.pdf')
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                flash('File already exists!', 'danger')
                return redirect(url_for('index'))
            form.file.data.save(file_path)
        
        new_ticket = Ticket(
            title=form.title.data,
            description=form.description.data,
            file_path=filename,
            user_id=current_user.id,
            recipient_ids=[form.recipient.data]  # Store as a single-item list
        )
        db.session.add(new_ticket)
        db.session.commit()
        flash('Ticket sent successfully!', 'success')
        return redirect(url_for('index'))
    
    # Show tickets where the user is the sender or a recipient
    if current_user.username == 'admin':
        tickets = Ticket.query.all()
    else: 
        tickets = Ticket.query.filter(
            (Ticket.user_id == current_user.id) | 
            (Ticket.recipient_ids.contains(current_user.id) & (Ticket.status != 2))
        ).all()
    
    # Preprocess to check if the current user is a recipient of each ticket
    user_recipient_status = []
    status_map = {0: 'Processing', 2: 'Rejected', 1: 'End'}
    status = []
    for ticket in tickets:
        if ticket.recipient_ids[-1] == current_user.id:
            user_recipient_status.append(1)
        else:
            user_recipient_status.append(None)
        status.append(status_map[ticket.status])
    recipient_usernames = {ticket.id: [User.query.get(recipient_id).username for recipient_id in ticket.recipient_ids] for ticket in tickets}
    return render_template('index.html', form=form, tickets=tickets, user_recipient_status=user_recipient_status,
                            recipient_usernames=recipient_usernames, status=status)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin')
@login_required
def admin():
    # if not current_user.is_authenticated or current_user.username != 'admin':
    #     return redirect(url_for('index'))
    # tickets = Ticket.query.all()
    return render_template('admin.html')

@app.route('/signup', methods=['GET', 'POST'])
@login_required
def signup():
    if current_user.username != 'admin':
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('index'))
    return render_template('signup.html', form=form)

@app.route('/remove', methods=['GET', 'POST'])
@login_required
def remove_user():
    if current_user.username != 'admin':
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('index'))
    form = RemoveUser()
    form.username.choices = [(user.id, user.username) for user in User.query.all() if (user.id != current_user.id)]
    print(form.username.choices)
    if form.validate_on_submit():
        user = User.query.filter(
            User.id == form.username.data).first()
        if user and form.username.data != "admin":
            db.session.delete(user)
            db.session.commit()
            flash(f'You removed username of {form.username}', 'success')
        else:
            flash(f'No user with username of {form.username} or you cannot remove yourself', 'failure')
        return redirect(url_for('index'))
    return render_template('remove_user.html', form=form)

@app.route('/forward_ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def forward_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.id not in ticket.recipient_ids or ticket.status == 2:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('index'))
    
    form = ForwardForm()
    form.recipient.choices = [(user.id, user.username) for user in User.query.all() if (user.id not in ticket.recipient_ids and user.id != current_user.id)]
    
    if form.validate_on_submit():
        new_recipient_id = form.recipient.data
        ticket.recipient_ids.append(new_recipient_id)
        
        if form.description.data and current_user.username == 'admin' and not form.file.data:
            filename = secure_filename(form.description.data + '.pdf')
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                flash('File already exists!', 'danger')
                return redirect(url_for('forward_ticket', ticket_id = ticket_id))
            ticket.description = form.description.data
            prev_name = os.path.join(app.config['UPLOAD_FOLDER'], ticket.file_path)
            ticket.file_path = filename
            os.rename(prev_name, file_path)
        
        if form.file.data and current_user.username == 'admin':
            filename = None
            if form.file.data and allowed_file(form.file.data.filename):
                filename = secure_filename(form.description.data + '.pdf')
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                form.file.data.save(file_path)
            if not filename:
                flash('No file name!', 'danger')
                return redirect(url_for('forward_ticket', ticket_id = ticket_id))
            ticket.filepath = filename
            ticket.description = form.description.data
        ticket.last_updated = datetime.utcnow()
        db.session.commit()
        flash('Ticket forwarded successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('forward_ticket.html', form=form, ticket=ticket)

@app.route('/reject_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def reject_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.username != 'admin' or ticket.status in [1,2]:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('index'))
    ticket.status = 2
    ticket.last_updated = datetime.utcnow()
    db.session.commit()
    flash('Ticket rejected successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/confirm/<int:ticket_id>', methods=['POST'])
@login_required
def confirm(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.username != 'warehouse' or ticket.status in [1,2] or current_user.id != ticket.recipient_ids[-1]:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('index'))
    ticket.status = 1
    ticket.last_updated = datetime.utcnow()
    db.session.commit()
    flash('Ticket confirmed successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/all', methods=['GET', 'POST'])
@login_required
def all():
    form = All()
    if current_user.username != 'admin':
        flash('Unathorized user', 'danger')
        return redirect(url_for('index'))
    if form.validate_on_submit():
        status = form.status.data
        return redirect(url_for('all_2', status=status))
    return render_template('all.html', form=form)

@app.route('/all/<int:status>', methods=['GET'])
@login_required
def all_2(status):
    form = All()
    if current_user.username != 'admin':
        flash('Unathorized user', 'danger')
        return redirect(url_for('index'))
    tickets = Ticket.query.filter(
        Ticket.status == status
    ).all()
    user_recipient_status = []
    status_map = {0: 'Processing', 2: 'Rejected', 1: 'End'}
    status_texts = [status_map[ticket.status] for ticket in tickets]

    for ticket in tickets:
        if ticket.recipient_ids and ticket.recipient_ids[-1] == current_user.id:
            user_recipient_status.append(1)
        else:
            user_recipient_status.append(None)

    recipient_usernames = {ticket.id: [User.query.get(recipient_id).username for recipient_id in ticket.recipient_ids] for ticket in tickets}

    return render_template('all.html', tickets=tickets, user_recipient_status=user_recipient_status, 
                           status=status_texts, recipient_usernames=recipient_usernames, form=form)

@app.route('/my_tickets', methods=['GET', 'POST'])
@login_required
def my_tickets():
    form = MineForm()
    if form.validate_on_submit():
        status = form.status.data
        ticket_type = form.type.data
        return redirect(url_for('my_tickets_2', ticket_type=ticket_type, status=status))

    return render_template('mine.html', form=form)

@app.route('/delete/<int:ticket_id>', methods=['DELETE', 'GET'])
@login_required
def remove_ticket(ticket_id):
    if current_user.username != 'admin':
        flash('Unathorized user', 'danger')
        return
    else:
        ticket = Ticket.query.filter(
            Ticket.id == ticket_id).first()
        file_name = ticket.file_path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
        os.remove(file_path)
        db.session.delete(ticket)
        db.session.commit()
        return redirect(url_for('all'))

@app.route('/my_tickets/<string:ticket_type>/<int:status>', methods=['GET'])
@login_required
def my_tickets_2(ticket_type, status):
    form = MineForm()
    if ticket_type == 'sent':
        tickets = Ticket.query.filter(
            Ticket.user_id == current_user.id,
            Ticket.status == status
        ).all()
    elif ticket_type == 'received':
        tickets = Ticket.query.filter(
            Ticket.recipient_ids.contains(current_user.id),
            Ticket.status == status
        ).all()
    else:
        flash('Bad URL', 'danger')
        return redirect(url_for('index'))

    user_recipient_status = []
    status_map = {0: 'Processing', 2: 'Rejected', 1: 'End'}
    status_texts = [status_map[ticket.status] for ticket in tickets]

    for ticket in tickets:
        if ticket.recipient_ids and ticket.recipient_ids[-1] == current_user.id:
            user_recipient_status.append(1)
        else:
            user_recipient_status.append(None)

    recipient_usernames = {ticket.id: [User.query.get(recipient_id).username for recipient_id in ticket.recipient_ids] for ticket in tickets}

    return render_template('mine.html', tickets=tickets, user_recipient_status=user_recipient_status, 
                           status=status_texts, recipient_usernames=recipient_usernames, form=form)
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug = True, port = 8000)
