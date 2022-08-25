from flask import Flask, url_for, session, redirect, render_template, request
from flask_session import Session
import random
import pymongo
from pymongo import MongoClient
from itertools import chain
import bcrypt
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, Email

app = Flask(__name__)

SESSION_TYPE = 'filesystem'
app.config.from_object(__name__)
Session(app)

app.secret_key = ''
app.config['RECAPTCHA_PUBLIC_KEY'] = ''
app.config['RECAPTCHA_PRIVATE_KEY'] = ''


msg = "Please log in"

cluster = MongoClient("")
db = cluster["Courseworkdata"]
questionCollection = db["Questions"]
provinceCollection = db["CzechiaProvince"]
users = db["Users"]


def getQuestion():

    totalquestions = questionCollection.find({})

    totalprovinces = provinceCollection.find({})

    #Initialises variables if they are not present
    if not "original_questions" in session:
        session["original_questions"]={}

    if not "totalP" in session:
        session["totalP"]=totalprovinces.count()

    if not "totalQ" in session:
        session["totalQ"]=totalquestions.count()
    

    question = questionCollection.find({"_id":session["questionNumber"]})

    for result in question:
            session["original_questions"] = {result["Question"] :[result['Answer1'], result['Answer2'], result['Answer3'], result['Answer4']]}

    #Used to split the dictionary into a list, then shuffle the list, and put it back into a dictionary
    originalList = list(session["original_questions"].values())

    splitList = list(chain.from_iterable(originalList))

    firstKey = list(session["original_questions"].keys())

    Answer = random.sample(splitList, len(splitList))

    finalDict = { firstKey[0]:[Answer[0], Answer[1], Answer[2], Answer[3]]}

    session["questions"] = finalDict

    return (session["questions"])

class UpdatePassword(FlaskForm): #Update Password form
    password = PasswordField('password', validators=[InputRequired('Please fill in the password'), Length(min=8, max=15, message='Must be between 8 to 15 characters')])
    password_current = PasswordField('password_current', validators=[InputRequired('Please fill in the password')])
class LoginForm(FlaskForm): #Login form
    username = StringField('username', validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired()])
    recaptcha = RecaptchaField()
class RegisterForm(FlaskForm): #Registration form
    regUsername = StringField('regUsername', validators=[InputRequired('Please fill in the username'), Length(min=4, max=15, message='Must be between 4 to 15 characters')])
    regPassword = PasswordField('regPassword', validators=[InputRequired('Please fill in the password'), Length(min=8, max=15, message='Must be between 8 to 15 characters')])
    email = StringField("Email",  [InputRequired("Please enter your email address."), Email("This field requires a valid email address")])

@app.route("/")
def home():

    if(session.get('username') is None):
        form = LoginForm()
        return render_template("login.html", msg = msg, s = session, form=form)

    user = users.find().sort("Games won",-1)
    players = []
    top = []
    newtop = []
    #Get top 10 players
    for info in user:
        players.append([info['username'], info['gamesWon']])
    top = (sorted(players, key=lambda x: int(x[1]), reverse=True))

    if len(top) > 10: 
        for get10 in range(10):
            newtop.append(top[get10])
        return render_template("index.html", s = session, active = newtop)

    return render_template("index.html", s = session, active = top)

@app.route("/profile/", methods=['GET', 'POST'])
def profile():

    if(session.get('username') is not None):
        user = users.find({'username' : session['username']})
        form = UpdatePassword()
        #Get user data for profile output
        for info in user:
            userData = {'Username' : info['username'], 'Games Played' : info['gamesPlayed'], 'Games won' : info['gamesWon']}
            desc = info['Desc']
        return render_template("profile.html", userdata = userData, s = session, desc = desc, form=form)

    form = LoginForm()
    return render_template("login.html", form=form)

@app.route('/profiledesc/', methods=['POST', 'GET'])
def profiledesc():

    description = request.form['description']
    if(session.get('username') is not None):
        #Used to update user description
        users.update_one({'username' : session['username']}, {"$set" : {'Desc' : description}})
        user = users.find({'username' : session['username']})

        for info in user:
            userData = {'Username' : info['username'], 'Games Played' : info['gamesPlayed'], 'Games won' : info['gamesWon']}
            desc = info['Desc']

        form = UpdatePassword()
        return render_template("profile.html", userdata = userData, s = session, desc = desc, form = form)

    form = LoginForm()
    return render_template("register.html", form=form)

@app.route("/search/", methods=['GET', 'POST'])
def search():#Method used to search for player information by accessing data from the database

    user = users.find({'username' : request.form['username']})
    userData = {}
    form = UpdatePassword()

    for info in user:
        userData = {'Username' : info['username'], 'Games Played' : info['gamesPlayed'], 'Games won' : info['gamesWon']}
        desc = info['Desc']

    if(len(userData) > 0):
        searched = True
        return render_template("profile.html", userdata = userData, s = session, desc = desc, searched = searched, form=form)

    notFound = True
    return render_template("profile.html", notFound = notFound, userdata = userData, s = session, form=form)

@app.route("/game/", methods=['GET', 'POST'])
def game():

    if(session.get('username') is None):
        form = LoginForm()
        return render_template("login.html", msg = msg, s = session, form=form)

    totalquestions = questionCollection.find({})

    if not "totalQ" in session:
        session["totalQ"]=totalquestions.count()
    #Initialises session variables
    session["provinces"] = []
    session["provinces"].clear()
    session["provinceCount"]=0
    session["questionCount"]=0
    session["questionNumber"]=0
    session["randomQuestions"] = []
    session["randomQuestions"].clear()
    x = 0
    #Adds and shuffles the order of the questions, and initialises the game
    for i in range(session["totalQ"]):
        session["randomQuestions"].append(x)
        x+=1
    random.shuffle(session["randomQuestions"])
    for i in session["randomQuestions"]:
        session["questionNumber"] = i

    return render_template("game.html", q = getQuestion(), s = session)

@app.route("/gamenext/", methods=['POST'])
def gamenext():

    if(session.get('username') is None):
        form = LoginForm()
        return render_template("login.html", msg = msg, s = session, form=form)

    if not "provinceCount" in session:
        session["provinceCount"]=0

    #Increments the question count
    session["questionCount"]+=1
    if session["questionNumber"] in session["randomQuestions"]:
        session["randomQuestions"].remove(session["questionNumber"])

    for i in session["randomQuestions"]:
        session["questionNumber"] = i
    
    if session["questionCount"] == session["totalQ"] or session["provinceCount"] == session["totalP"]:
        if(session["questionCount"] == session["totalQ"]): #If the player lost the game, 1 game played is added
            users.update_one({'username' : session['username']}, {'$inc': {'gamesPlayed' : 1}})

        else: #If the player won the game, a game played and game won is added
            users.update_one({'username' : session['username']}, {'$inc': {'gamesPlayed' : 1, 'gamesWon' : 1}})

        return render_template("game.html", p = session["provinces"], totalP = session["totalP"], totalQ = session["totalQ"], s = session)
    else:

        return render_template("game.html", q = getQuestion(),  p = session["provinces"], s = session)

@app.route('/gamechck/', methods=['POST'])
def gamechck():#Method to check if question answer is correct

 questions = getQuestion()
 correct = 0
 if(session.get('username') is None):
    form = LoginForm()
    return render_template("login.html", msg = msg, s = session)

 for i in questions.keys():
  answered = request.form[i]
  if session["original_questions"][i][0] == answered:
   correct = 1
   session["provinceCount"]+=1
   session["provinces"].append(request.form["Province"])
   
 return render_template("gamechck.html", a = correct, q = questions, c = session["original_questions"][i][0],  p = session["provinces"], s = session)

@app.route('/login/', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            #Standard login credentials check
            user = users.find_one({'username' : request.form['username']})
            if user:
                if bcrypt.hashpw(request.form['password'].encode('utf-8'), user['password']) == user['password']:
                    session['username'] = request.form['username']
                    return redirect(url_for('home'))

            wrongLogin = True
            return render_template("login.html", wrongLogin = wrongLogin, s = session, form=form, msg = msg)
    return render_template("login.html", s = session, form=form, msg = msg)

@app.route('/register/', methods=['GET', 'POST'])
def register():

    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = users.find_one({'username' : request.form['regUsername']})
            userEmail = users.find_one({'Email' : request.form['email']})
            
            if user is None and userEmail is None:
                #Hashes the password and creates a new user in the database
                hashedpass = bcrypt.hashpw(request.form['regPassword'].encode('utf-8'), bcrypt.gensalt())
                users.insert({'username' : request.form['regUsername'], 'password' : hashedpass, 'email' : request.form['email'], 'gamesPlayed' : 0, 'gamesWon' : 0, 'Desc' : "Introduce yourself here"})
                session['username'] = request.form['regUsername']
                return redirect(url_for('home'))

            elif userEmail is not None:
                #Outputs a message if the email is wrong
                wrongEmail = True
                return render_template("register.html", wrongEmail = wrongEmail, s = session, form=form)

            wrongRegister = True
            return render_template("register.html", wrongRegister = wrongRegister, s = session, form=form)

    return render_template("register.html", s = session, msg = msg, form=form)

@app.route('/logout/')
def logout():

    form = LoginForm()
    session.pop('username', None)
    return render_template("login.html", s = session, msg = msg, form=form)

@app.route('/updatepass/', methods=['GET', 'POST'])
def updatePass():

    form = UpdatePassword()
    user = users.find({'username' : session['username']})
    userData = {}

    for info in user:
        userData = {'Username' : info['username'], 'Games Played' : info['gamesPlayed'], 'Games won' : info['gamesWon']}
        desc = info['Desc']

    if request.method == 'POST':

        if form.validate_on_submit():

            user = users.find_one({'username' : session['username']})
            #If credentials match up, change to new password
            if bcrypt.hashpw(request.form['password_current'].encode('utf-8'), user['password']) == user['password']:

                hashedpass = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
                users.update_one({'username' : session['username']}, {"$set" : {'password' : hashedpass}})
                return render_template("profile.html", s = session, userdata = userData, form=form, passchanged = 'Password has been changed.')

            wrongLogin = True
            session.pop('username', None)
            form = LoginForm()

            return render_template("login.html", s = session, form=form, msg = 'Incorrect password, please login again.')

    return render_template("profile.html", userdata = userData, s = session, desc = desc, form=form)


if __name__ == '__main__':
    from os import environ
    app.run(debug=False)
