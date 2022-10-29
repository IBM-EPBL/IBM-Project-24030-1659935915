from flask import Flask, render_template, request, redirect, url_for, session
import ibm_db
import re
app = Flask(__name__)

app.secret_key='a'

conn = ibm_db.connect("DATABASE=bludb;HOSTNAME=9938aec0-8105-433e-8bf9-0fbb7e483086.c1ogj3sd0tgtu0lqde00.databases.appdomain.cloud; PORT=32459; Security=SSL;SSLServerCertificate=DigiCertGlobalRootCA.crt;UID=dmz49400; PWD=gyRzSBXn1Biv7bk5;",'','')


@app.route('/')
def home():
    return render_template('home.html')
@app.route('/registertemp',methods=["POST","GET"])
def registertemp():
    return render_template("register.html")
@app.route('/uploaddata',methods =['GET','POST'])
def register():
    msg = ''
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        address = request.form['address']  
        stmt = ibm_db.prepare(conn, 'SELECT * FROM user WHERE username = ?')
        ibm_db.bind_param(stmt, 1, username)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt) 
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'^[A-Za-z0-9_.-]*$', username):
            msg = 'name must contain only characters and numbers !'
        else:
            prep_stmt = ibm_db.prepare(conn,'INSERT INTO user(firstname, lastname, username, email, password, address) VALUES(?, ?, ?, ?, ?, ?)')
            ibm_db.bind_param(prep_stmt, 1, firstname)
            ibm_db.bind_param(prep_stmt, 2, lastname)
            ibm_db.bind_param(prep_stmt, 3, username)
            ibm_db.bind_param(prep_stmt, 4, email)
            ibm_db.bind_param(prep_stmt, 5, password)
            ibm_db.bind_param(prep_stmt, 6, address)
            ibm_db.execute(prep_stmt)
            msg = 'Dear % s You have successfully registered!'%(username)
    return render_template('register.html',a = msg,indicator="success")
    return render_template('register.html')
@app.route('/login',methods=["POST","GET"])
def login():
    return render_template("login.html")

@app.route('/logindata',methods=["POST","GET"])
def logindata():
    global userid
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        stmt = ibm_db.prepare(conn,'SELECT * FROM user WHERE username = ? AND password = ?')
        ibm_db.bind_param(stmt,1,username)
        ibm_db.bind_param(stmt,2,password)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)
        if account:
            session['loggedin'] = True
            session['username'] = account['USERNAME']
            return redirect(url_for('dashboard'))
            
        
        else:
            msg = 'Incorrect username / password !'
            return render_template('login.html', b = msg,indicator="failure")
    return render_template('userdashboard.html',a = msg,indicator="success")
    return render_template('userdashboard.html')
    
@app.route('/dashboard')
def dashboard():
    if 'id' in session:
        username = session['username']
    return render_template('userdashboard.html',name=username)
    return render_template("userdashboard.html")
@app.route('/profile',methods=["POST","GET"])
def profile():
    if 'id' in session:
        uid = session['id']
        stmt = ibm_db.prepare(conn,'SELECT * FROM user WHERE id = ?')
        ibm_db.bind_param(stmt, 1, uid)    
        ibm_db.execute(stmt)
        acc = ibm_db.fetch_assoc(stmt)
        return render_template('userprofile.html',fullname=acc[2]+acc[3],username=acc[4],email=acc[5],address=acc[7])
        return render_template("userprofile.html")
@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/adminpage')
def adminpage():
    return render_template('admin dashboard.html')

@app.route('/adminlog',methods=["POST","GET"])
def adminlog():
    msg = ''
    email = request.form['email']
    password = request.form['password']
    stmt = ibm_db.prepare(conn, 'SELECT * FROM admininfo  WHERE email = ?  and password = ?')
    ibm_db.bind_param(stmt,1, email)
    ibm_db.bind_param(stmt,2, password)
    ibm_db.execute(stmt)
    logged = ibm_db.fetch_assoc(stmt)
    if(logged):
        msg = 'successfully loggedin'
        return render_template("admin dashboard.html",a=msg)
    else:
        return render_template("admin.html",a="Incorrect email/password")

if __name__ == '__main__':
    app.debug=True
    app.run(host='0.0.0.0',port=8080)
