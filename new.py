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
import os
import asyncio
import aiohttp

key = '5fbe07b236e55c0d017aa5592a047478'
os.environ['translation_token'] = '919765:66d7599c6ff3c'
os.environ['youtube_apikey'] = 'AIzaSyA_n0dei0p18IsuPAs3hmdSpEIksG_-JZY'

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
    pop = []
    headers = {"accept": "application/json"}
    def find_movies(key_word, page):
        url_results = f'https://api.themoviedb.org/3/discover/movie?&page={page}&api_key={key}&with_keywords={key_word}&sort_by=popularity.desc&primary_release_date.lte=2024-09-01'
        try:
            response = requests.get(url_results, headers=headers).json()
        except Exception as e:
            print('Error in connecting to the TMDB server')
            return None
        return response
    
    #print(queries)
    dic_movie = {}
    for query in queries:
        results_temp = []
        keywords = []
        url_keywords = f"https://api.themoviedb.org/3/search/keyword?api_key={key}&query={query}"
        try:
            response = requests.get(url_keywords, headers=headers).json()
            if response == None:
                continue
        except Exception as e:
            print('Error in connecting to the TMDB server')
            print(e)
            continue

        total_pages = response['total_pages']
        for id in response['results']:
            keywords.append(id['id'])
        if len(keywords) > 2:
            keywords = keywords[:2]
        for r in keywords:
            end = False
            for i in range(1, int(total_pages)+1):
                temp = find_movies(r, page=i)['results']
                for mov in temp:
                    if mov['popularity'] < 50:
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

# Fetch YouTube links (Asynchronous)
@app.route("/youtube/", methods=["GET"])
def youtube():
    search_query = request.args.get('search_query')
    length = request.args.get('length', 'both')
    result_num = int(request.args.get('result_num', 1))
    type_ = int(request.args.get('type', 0))

    if not search_query:
        return jsonify({"error": "Missing 'search_query' parameter"}), 400

    API_KEY = os.getenv('youtube_apikey')
    def fetch(duration):
        base_url = f'https://www.googleapis.com/youtube/v3/search?part=snippet&videoDuration={duration}&maxResults={result_num}&q={search_query}&key={API_KEY}&type=video'
        
        # Modify URL for video category
        if type_ == 10:
            url = f'{base_url}&videoCategoryId=10'
        elif type_ == 1:
            url = f'{base_url}&videoCategoryId=1'
        else:
            url = base_url
        return url
    
    # Make the asynchronous request using aiohttp
    async def fetch_youtube_links(url):
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                data = await response.json()
                print(data)
                results = [
                    f"https://www.youtube.com/watch?v={item['id']['videoId']}"
                    for item in data['items']
                ]
                return results

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = []
    if length == 'both':
        lens = ['short', 'medium']
    else:
        lens = [length]
    for lenth in lens:
        results += loop.run_until_complete(fetch_youtube_links(fetch(lenth)))
    return results

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug = True, port = 8888)

