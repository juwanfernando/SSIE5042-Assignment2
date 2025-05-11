'''
The start of the application has all the routes and the app invocation
'''
import os
import logging
from flask import Flask, render_template, send_from_directory, request, redirect, url_for, flash, session, jsonify
from setup.db import db, xss, sqlinjection, fuzzing
from setup.file import fileaccess
from setup.execution import execute
from markupsafe import escape
import re
from werkzeug.utils import secure_filename
import json
from oauthlib import oauth2
import requests

APP = Flask(__name__)
APP.secret_key = 'someSecret'

# Configure OAuth
CLIENT_ID = os.environ['GOOGLE_CLIENT_ID']
CLIENT_SECRET = os.environ['GOOGLE_CLIENT_SECRET']

DATA = {
        'response_type':"code",
        'redirect_uri':"http://127.0.0.1:5001/login/callback",
        'scope': 'https://www.googleapis.com/auth/userinfo.email',
        'client_id':CLIENT_ID,
        'prompt':'consent'}

URL_DICT = {
        'google_oauth' : 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_gen' : 'https://oauth2.googleapis.com/token',
        'get_user_info' : 'https://www.googleapis.com/oauth2/v3/userinfo'
        }

# Create a Sign in URI
CLIENT = oauth2.WebApplicationClient(CLIENT_ID)
REQ_URI = CLIENT.prepare_request_uri(
    uri=URL_DICT['google_oauth'],
    redirect_uri=DATA['redirect_uri'],
    scope=DATA['scope'],
    prompt=DATA['prompt'])

#**************
#Misc Routes
#**************
@APP.route('/')
def index():
    '''
    Route handler for the home page
    '''
    if 'user' in session:
        return render_template('index.html', user=session['user'])
    return render_template('login.html')

    #return render_template('index.html')

@APP.route('/login')
def login():
    return redirect(REQ_URI)

@APP.route('/login/callback')
def authorize():
    "Redirect after Google login & consent"

    # Get the code after authenticating from the URL
    code = request.args.get('code')

    # Generate URL to generate token
    token_url, headers, body = CLIENT.prepare_token_request(
            URL_DICT['token_gen'],
            authorisation_response=request.url,
            # request.base_url is same as DATA['redirect_uri']
            redirect_url=request.base_url,
            code=code)

    # Generate token to access Google API
    token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(CLIENT_ID, CLIENT_SECRET))

    # Parse the token response
    CLIENT.parse_request_body_response(json.dumps(token_response.json()))

    # Add token to the  Google endpoint to get the user info
    # oauthlib uses the token parsed in the previous step
    uri, headers, body = CLIENT.add_token(URL_DICT['get_user_info'])

    # Get the user info
    response_user_info = requests.get(uri, headers=headers, data=body)
    info = response_user_info.json()

    #return redirect('/')
    session['user'] = {
        'email': info['email']
    }
    
    return redirect(url_for('index'))
        
@APP.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


@APP.route('/robots.txt')
def robots():
    '''
    Route handler for the home page
    '''
    return send_from_directory(APP.static_folder, 'robots.txt')

@APP.route('/mysecret/')
def secret():
    '''
    Route handler for the home page
    '''
    return render_template('./mysecret.html')

@APP.route('/reset/')
def reset():
    '''
    Route handler page that resets the hole database
    '''
    db.create(True)
    return redirect(url_for('index'))
#**************
#End Misc Routes
#**************

#*************
#XSS Routes
#*************
@APP.route('/xss/reflected/', methods=['GET', 'POST'])
def xss_reflected():
    '''
    Route handler for the reflected cross site scripting
    '''
    name = None
    if request.values.get('name'):
        name = escape(request.values['name'])        
        if not re.match(r'^[a-zA-Z0-9\s-]+$', name):
            name = "Invalid Input"
    return render_template('./xss/reflected.html', name=name)

@APP.route('/xss/stored/', methods=['GET', 'POST'])
def xss_stored():
    '''
    Route handler for the stored cross site scripting
    '''
    if request.method == 'POST':
        name = request.form['name']
        comment = request.form['comment']
        parentid = request.form['parentID']
        if name and comment:
            xss.addcomment(name, comment, parentid)
    all_rows = xss.getcomments()
    return render_template('./xss/stored.html', comments=all_rows)
#**************
#End XSS Routes
#**************

#**************
#SQLI Routes
#**************
@APP.route('/sqli/simple/', methods=['GET', 'POST'])
def sqli_simple():
    '''
    Route handler for the simple sql injection
    '''
    comments = None
    search = ''
    if request.method == 'POST':
        search = request.form['search']
    comments = sqlinjection.search(search)
    return render_template('./sqli/simple.html', comments=comments[1],
                           search=search, sqlquery=comments[0])

@APP.route('/sqli/simpleescape/', methods=['GET', 'POST'])
def sqli_simpleescape():
    '''
    Route handler for the simple sql escape injection
    '''
    comments = None
    search = ''
    if request.method == 'POST':
        search = request.form['search']
        search = search.replace(";--", " ")
    comments = sqlinjection.search(search)
    return render_template('./sqli/simpleescape.html', comments=comments[1],
                           search=search, sqlquery=comments[0])

@APP.route('/sqli/blind/', methods=['GET', 'POST'])
def sqli_blind():
    '''
    Route handler for the Blind sql injection page
    '''
    name = None
    phone = None
    secret = None
    display = 1
    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        secret = request.form['secret']
        if name and phone and secret and display:
            flash('Your submission has been saved.', 'success')
            sqlinjection.search_insert(name, phone, secret)
        else:
            flash('Make sure you are filling out all the fields', 'error')
    return render_template('./sqli/blindinjection.html', name=name, phone=phone,
                           secret=secret, display=display)

#**************
#End SQLI Routes
#**************

#**************
#File Routes
#**************
@APP.route('/file/traversal/', methods=['GET'])
def file_traversal():
    '''
    Route handler for the file traversal page
    '''
    current_path = fileaccess.fileaccess_getuploadspath()
    entered_path = ""
    file = None
    results = None
    if request.values.get('path'):
        entered_path = request.values.get('path')
        if not fileaccess.is_safe_path(current_path, entered_path):
            return render_template('./files/forbidden.html')
        current_path = os.path.join(current_path, *(entered_path.replace('\\', '/').split("/")))
    if request.values.get('file'):
        #file = request.values.get('file')
        file = secure_filename(request.values.get('file'))
        if not fileaccess.is_safe_path(current_path, file):
            return render_template('./files/forbidden.html')
        if fileaccess.fileaccess_fileexists(current_path, file):
            return send_from_directory(current_path, file)
    results = fileaccess.fileaccess_getfilesandfolders(current_path)
    return render_template('./files/traversal.html', path=entered_path, results=results, file=file)
#**************
#End File Routes
#**************

#**************
# Execution Routes
#**************
@APP.route('/execution/simple/', methods=['GET', 'POST'])
def execution_simple():
    '''
    Route handler for the execute simple page
    '''
    ip_address = None
    results = None
    if request.method == 'POST':
        ip_address = request.form['ip']
        results = execute.execute_ping(ip_address)
    return render_template('./execution/simple.html', ip=ip_address, results=results)
#**************
#End Execution Routes
#**************

#**************
#Fuzzing Routes
#**************
@APP.route('/fuzzing/simple/', methods=['GET'], defaults={'id':None})
@APP.route('/fuzzing/simple/<int:id>/', methods=['GET'])
def fuzzing_simple(id):
    data = None
    if id:
        data = fuzzing.getFuzzing(id)
    return render_template('./fuzzing/simple.html', data=data)
#**************
#End Execution Routes
#**************

#**************
#Filters
#**************
@APP.template_filter('commentcut')
def commentcut(comments, commentid):
    '''
    A filter used on the comments to get just
    the comments that pertain to the id
    '''
    if comments:
        return (x for x in comments if x[4] == commentid)
    return None
#**************
#End Filters
#**************

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logging.info("Starting db Creation")
    db.create(False)
    logging.info("DB creation script complete.\r\nStarting the server")
    APP.run(debug=True, host='0.0.0.0', port=5001)
