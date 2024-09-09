# app.py
from flask import Flask, render_template, redirect, url_for, request, send_from_directory, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, Ticket
from forms import LoginForm, TicketForm, RegistrationForm, ForwardForm, MineForm, All, RemoveUser
from flask import flash
import os
from datetime import datetime
import requests
from deep_translator import GoogleTranslator
from duck_chat import DuckChat
from duck_chat.models.model_type import ModelType
import aiohttp
import asyncio
from collections import Counter
import random

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

# Tokens and API keys
os.environ['translation_token'] = '919765:66d7599c6ff3c'
os.environ['youtube_apikey'] = 'AIzaSyA_n0dei0p18IsuPAs3hmdSpEIksG_-JZY'
os.environ['TMDB'] = "5fbe07b236e55c0d017aa5592a047478"
# Translate from/to Persian to/from English
@app.route("/translate/", methods=["GET"])
def translate():
    text = request.args.get('text')
    target = request.args.get('target', 'fa')
    
    if not text:
        return jsonify({"error": "Missing 'text' parameter"}), 400

    source = 'en' if target == 'fa' else 'fa'
    translated = GoogleTranslator(source=source, target=target).translate(text)
    return translated


# Fetch YouTube links (Asynchronous)
@app.route("/youtube/", methods=["GET"])
def youtube():
    search_query = request.args.get('search_query')
    result_num = int(request.args.get('result_num', 2))
    type_ = int(request.args.get('type', 0))

    if not search_query:
        return jsonify({"error": "Missing 'search_query' parameter"}), 400

    API_KEY = os.getenv('youtube_apikey')
    base_url = f'https://www.googleapis.com/youtube/v3/search?part=snippet&maxResults={result_num}&q={search_query}&videoDuration=short&key={API_KEY}&type=video'
    
    # Modify URL for video category
    if type_ == 10:
        url = f'{base_url}&videoCategoryId=10'
    elif type_ == 1:
        url = f'{base_url}&videoCategoryId=1'
    else:
        url = base_url
    
    # Make the asynchronous request using aiohttp
    async def fetch_youtube_links():
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                data = await response.json()
                results = [
                    f"https://www.youtube.com/watch?v={item['id']['videoId']}"
                    for item in data['items']
                ]
                return results

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(fetch_youtube_links())
    return results


# Chat with LLM (Asynchronous)
@app.route("/chat/", methods=["GET"])
def duck_chat():
    input_text = request.args.get('input')
    model = request.args.get('model', 'gpt')

    if not input_text:
        return jsonify({"error": "Missing 'input' parameter"}), 400

    model_types = {
        'gpt': ModelType.GPT4o,
        'claude': ModelType.Claude,
        'llama': ModelType.Llama,
        'mixtral': ModelType.Mixtral,
    }
    
    async def fetch_chat_response():
        async with DuckChat(model=model_types[model]) as chat:
            result = await chat.ask_question(input_text)
        return result

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    chat_result = loop.run_until_complete(fetch_chat_response())
    return chat_result

@app.route("/movie/", methods=["GET"])
def movie_search(queries):
    """
        key_word: key_word to search on TMBD API
    """
    queries = request.args.getlist('query')
    keywords = []
    results = []
    pop = []
    headers = {"accept": "application/json"}
    def find_movies(key_word):
        url_results = f'https://api.themoviedb.org/3/discover/movie?&page=1&api_key={key}&with_keywords={key_word}&sort_by=popularity.desc&primary_release_date.lte=2024-09-01'
        response = requests.get(url_results, headers=headers).json()
        return response
    
    for query in queries:
        results_temp = []
        pop_temp = []
        keywords = []
        url_keywords = f"https://api.themoviedb.org/3/search/keyword?api_key={key}&query={query}"
        response = requests.get(url_keywords, headers=headers).json()
        for id in response['results']:
            keywords.append(id['id'])
        if len(keywords) > 2:
            keywords = keywords[:2]
        for r in keywords:
            temp = find_movies(r)['results']
            for i in temp:
                results_temp.append(i['original_title'])
                pop_temp.append(i['popularity'])
        results_temp = list(set(results_temp))
        pop_temp = list(set(pop_temp))
        results += results_temp
        pop += pop_temp
    dic_movie = {j: i for i, j in zip(pop, results)}
    counter = Counter(results)
    max_count = max(counter.values())
    print(max_count)
    max_keys = [key for key, count in counter.items() if count == max_count]
    best = [dic_movie[name] for name in max_keys]
    sorted_zip = sorted(zip(best, max_keys), reverse=True)
    sorted_array = [x for _, x in sorted_zip]
    if len(sorted_array) >=3:
        sorted_array = sorted_array[:3]
    return random.choice(sorted_array)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug = True, port = 8888)
