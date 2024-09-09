# app.py
from flask import Flask, render_template, redirect, url_for, request, send_from_directory, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db
from collections import Counter
import random
import requests
import ssl

key = '5fbe07b236e55c0d017aa5592a047478'

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

@app.route("/movie/", methods=["GET"])
def movie_search():
    """
        key_word: key_word to search on TMBD API
    """
    queries = request.args.getlist('query')
    keywords = []
    results = []
    headers = {"accept": "application/json"}
    def find_movies(key_word, page):
        url_results = f'https://api.themoviedb.org/3/discover/movie?&page={page}&api_key={key}&with_keywords={key_word}&sort_by=popularity.desc&primary_release_date.lte=2024-09-01'
        response = requests.get(url_results, headers=headers).json()
        return response
    
    #print(queries)
    dic_movie = {}
    for query in queries:
        results_temp = []
        keywords = []
        url_keywords = f"https://api.themoviedb.org/3/search/keyword?api_key={key}&query={query}"
        try:
            response = requests.get(url_keywords, headers=headers).json()
        except ssl.SSLError as e:
            print('Error in connecting to the TMDB server')
            raise
        total_pages = response['total_pages']
        for id in response['results']:
            keywords.append(id['id'])
        if len(keywords) > 5:
            keywords = keywords[:5]
        for r in keywords:
            end = False
            for i in range(1, int(total_pages)+1):
                temp = find_movies(r, page=i)['results']
                for mov in temp:
                    if mov['popularity'] < 10:
                        end = True
                        break
                    results_temp.append(mov['original_title'])
                    dic_movie[mov['original_title']] = mov['popularity']
                if end:
                    break
        results_temp = list(set(results_temp))
        results += results_temp
    counter = Counter(results)
    max_count = max(counter.values())
    max_keys = [key for key, count in counter.items() if count == max_count]
    sorted_zip = {key: dic_movie[key] for key in max_keys}
    sorted_array = sorted(sorted_zip, key = sorted_zip.get, reverse=True)
    if len(sorted_array) >=3:
        sorted_array = sorted_array[:3]
    return random.choice(sorted_array)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug = True, port = 8888)

