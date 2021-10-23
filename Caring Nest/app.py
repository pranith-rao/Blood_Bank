from flask import Flask,redirect,render_template,url_for,request,flash,session
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy
from sqlalchemy import func
from passlib.hash import sha256_crypt
import os
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"]="mysql://root:@localhost/blood_bank_hack"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = os.urandom(16)
db = SQLAlchemy(app)

class Admin(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50),nullable=False,unique=True)
    email = db.Column(db.String(100),nullable=False,unique=True)
    password = db.Column(db.String(255),nullable=False)

    def __repr__(self):
        return "<Admin '{}'>".format(self.name)

class Receptionist(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50),nullable=False,unique=True)
    email = db.Column(db.String(100),nullable=False,unique=True)
    phone = db.Column(db.String(15),nullable=False)
    address = db.Column(db.String(255),nullable=False)
    gender = db.Column(db.String(15),nullable=False)
    password = db.Column(db.String(255),nullable=False)

    def __repr__(self):
        return "<Receptionist '{}'>".format(self.name)
    
    
    class Outh_details(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    Outh_name = db.Column(db.String(50),nullable=False,unique=True)
    Outh_email = db.Column(db.String(100),nullable=False,unique=True)
    Outh_phone = db.Column(db.String(15),nullable=False)
    

    def __repr__(self):
        return "<Outh_details '{}'>".format(self.name)

class Hospital(db.Model):
    hospitalid = db.Column(db.Integer,unique=True,primary_key=True)
    name = db.Column(db.String(50),nullable=False,unique=True)
    phno = db.Column(db.String(255),nullable=False)
    address = db.Column(db.String(100),nullable=False,unique=True)
    password = db.Column(db.String(255),nullable=False)

    def __repr__(self):
        return "<Hospital '{}'>".format(self.name)

class Blood_bank(db.Model):
    blood_bank_no = db.Column(db.Integer,unique=True,primary_key=True)
    name = db.Column(db.String(50),nullable=False,unique=True)
    phone = db.Column(db.String(12),nullable=False)
    address = db.Column(db.String(255),nullable=False)
    password = db.Column(db.String(255),nullable=False)

    def __repr__(self):
        return "<Blood_bank '{}'>".format(self.name)

class Donor(db.Model):
    candidate_no = db.Column(db.Integer,primary_key=True,unique=True)
    name = db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(100),nullable=False,unique=True)
    phone = db.Column(db.String(12),nullable=False)
    address = db.Column(db.String(255),nullable=False)
    gender = db.Column(db.String(255),nullable=False)
    blood_type = db.Column(db.String(5),nullable=False)

    #try
    blood_bank = db.Column(db.Integer,nullable=False)
    Donations = db.relationship('Donation', backref='donor', lazy=True,cascade='all,delete')

    def __repr__(self):
        return "<Donor '{}'>".format(self.name)

class Donation(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    units = db.Column(db.String(15),nullable=False)
    blood_type = db.Column(db.String(12),nullable=False)
    blood_bank = db.Column(db.Integer, nullable=False)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.candidate_no'),
        nullable=False)


    def __repr__(self):
        return "<Donation '{}'>".format(self.id)


db.create_all()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/Adminreg')
def Adminreg():
    return render_template('Admin_reg.html')

@app.route('/Adminlog')
def Adminlog():
    return render_template('Admin_log.html')

@app.route('/bankforpass')
def bankforpass():
    return render_template('change_passbank.html')

@app.route('/order')
def order():
    if 'receptionist' in session:
        data = Blood_bank.query.all()
        return render_template('order.html',data=data)
    return redirect(url_for("receplog"))


@app.route('/Admindash')
def Admindash():
    if 'admin' in session:
        hospital = Hospital.query.count()
        donar = Donor.query.count()
        bank = Blood_bank.query.count()
        recep = Receptionist.query.count()
        return render_template('admin_dash.html',data=[hospital,donar,bank,recep])
    return redirect(url_for("Adminlog"))

@app.route('/Hosreg')
def Hosreg():
    if 'admin' in session:
        return render_template('Hos_reg.html')
    return redirect(url_for("Adminlog"))

@app.route('/Hoslog')
def Hoslog():
    return render_template('Hos_log.html')

@app.route('/Hosdash')
def Hosdash():
    if 'hospital' in session:
        recep = Receptionist.query.count()
        donar = Donor.query.count()
        bank = Blood_bank.query.count()
        return render_template('Hos_dash.html',data=[recep,donar,bank])
    return redirect(url_for("Hoslog"))

@app.route('/Bloodbank_reg')
def Bloodbank_reg():
    if 'admin' in session:
        return render_template('bloodbank_form.html')
    return redirect(url_for("Adminlog"))

@app.route('/bloodbank_login')
def bloodbank_login():
    return render_template('bloodbank_login.html')

@app.route("/bloodbank_dash")
def bloodbank_dash():
    if 'blood_bank' in session:
        hospital = Hospital.query.count()
        donar = Donor.query.count()
        bank = Blood_bank.query.count()
        return render_template("bloodbank_dash.html",data=[hospital,donar,bank])
    return redirect(url_for("bloodbank_login"))

@app.route('/recepreg')
def recepreg():
    if 'hospital' in session:
        return render_template('Recep_reg.html')
    return redirect(url_for("Hoslog"))

@app.route('/receplog')
def receplog():
    return render_template('Recep_log.html') 

@app.route('/recepdash')
def recepdash():
    if 'receptionist' in session:
        hospital = Hospital.query.count()
        donar = Donor.query.count()
        bank = Blood_bank.query.count()
        return render_template('Recep_dash.html',data=[hospital,donar,bank])
    return redirect(url_for("receplog"))

@app.route('/donorform')
def donorform():
    if 'blood_bank' in session:
        return render_template('Donor_from.html')
    return redirect(url_for("bloodbank_login"))

@app.route('/donordetails')
def donordetails():
    if 'blood_bank' in session:
        return render_template('Donation_details.html')
    return redirect(url_for("bloodbank_login"))

@app.route('/forgotpassword')
def forgotpassword():
    return render_template('forgot_password.html') 

@app.route('/forgotpassword_hos')
def forgotpassword_hos():
    return render_template('forgotpass_hos.html') 

@app.route('/forgotpassword_recep')
def forgotpassword_recep():
    return render_template('forgotpass_recep.html') 

@app.route('/changepassword')
def changepassword():
    return render_template('Change_password.html')

@app.route('/fcpassword_bank')
def fcpassword_bank():
    return render_template('forgot_password_bank.html')

@app.route('/changepasswordrecep')
def changepasswordrecep():
    return render_template('changepasswordrecep.html') 

@app.route('/Hos_list')
def Hos_list():
    data = Hospital.query.all()
    return render_template('Hos_list.html',data=data)

@app.route('/blood_list')
def blood_list():
    data = Blood_bank.query.all()
    return render_template('Bloodbank_list.html',data=data)

@app.route('/blood_list1')
def blood_list1():
    data = Blood_bank.query.all()
    return render_template('Bloodbank_list1.html',data=data)

@app.route('/Recep_list')
def Recep_list():
    data = Receptionist.query.all()
    return render_template('Recep_list.html',data=data)

@app.route('/Recep_list1')
def Recep_list1():
    data = Receptionist.query.all()
    return render_template('Recep_list1.html',data=data)


@app.route('/donor_list')
def donor_list():
    data = Donor.query.all()
    return render_template('donor_list.html',data=data)

@app.route('/donor_list_1')
def donor_list_1():
    data = Donor.query.all()
    return render_template('donor_list1.html',data=data)

@app.route('/donor_list1')
def donor_list1():
    data = Donation.query.all()
    return render_template('donor_list_1.html',data=data)

@app.route('/donor_list01')
def donor_list01():
    data = Donation.query.all()
    return render_template('donor_list_01.html',data=data)

#code backened
@app.route("/admin_reg_data",methods=['POST'])
def admin_reg_data():
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['pass']
        repass = request.form['repass']
        if password == repass:
            name_check = Admin.query.filter_by(name=name).first()
            if not name_check:
                email_check = Admin.query.filter_by(email=email).first()
                if not email_check:
                    hash_pasw = sha256_crypt.hash(password)
                    admin = Admin(name=name,email=email,password=hash_pasw)
                    db.session.add(admin)
                    db.session.commit()
                    flash("Registration success","success")
                    return redirect(url_for("Adminlog"))
                flash("Email already exists",'error')
                return redirect(url_for("Adminreg"))
            flash("Name already exists", 'error')
            return redirect(url_for("Adminreg"))
        flash("Password mismatch", 'error')
        return redirect(url_for("Adminreg"))

#admin-login
@app.route("/admin_login_data",methods=['POST'])
def admin_login_data():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['pass']
        response = Admin.query.filter_by(email=email).first()
        if not response:
            flash("Email ID not registered",'error')
            return redirect(url_for("Adminlog"))
        else:
            checkpass = sha256_crypt.verify(password,response.password)
            if email == response.email and checkpass == True:
                session['admin'] = True
                session['admin_name']= response.name
                session['email'] = response.email
                flash('You were successfully logged in',"success")
                return redirect(url_for("Admindash"))
            else:
                flash('Invalid Credentials',"error")
                return redirect(url_for("Adminlog"))

#logout for all
@app.route("/logout")
def logout():
    session.clear()
    flash('Logged out successfully',"success")
    return redirect(url_for("index"))

@app.route("/recep_reg_data",methods=['POST'])
def recep_reg_data():
    if request.method == 'POST':
        if 'hospital' in session:
            name = request.form['name']
            email = request.form['email']
            address = request.form['address']
            gender = request.form['gender']
            phone = request.form['phone']
            has_pasw = sha256_crypt.hash(phone)
            check_name=Receptionist.query.filter_by(name=name).first()
            if not check_name:
                check_email = Receptionist.query.filter_by(email=email).first()
                if not check_email:
                    reception = Receptionist(name=name,email=email,address=address,phone=phone,gender=gender,password=has_pasw)
                    db.session.add(reception)
                    db.session.commit()
                    flash("Receptionist registered successfully","success")
                    return redirect(url_for("Hosdash"))
                flash("Email already exists", 'error')
                return redirect(url_for("recepreg"))
            flash("Name already exists", 'error')
            return redirect(url_for("recepreg"))
        flash("You are not authorized to perform this action","error")
        return redirect(url_for("recepreg"))

@app.route("/recep_log_data",methods=['POST'])
def recep_log_data():
    if request.method == 'POST':
        email = request.form['email']
        pasw = request.form['passw']
        check_email = Receptionist.query.filter_by(email=email).first()
        if check_email:
            check_pass = sha256_crypt.verify(pasw,check_email.password)
            if check_pass:
                session['reception_id'] = check_email.id
                session['reception_name'] = check_email.name
                session['reception_email'] = check_email.email
                session['receptionist'] = True
                flash("Logged in ","success")
                return redirect(url_for("recepdash"))
            flash("Invalid credentials ", "error")
            return redirect(url_for("receplog"))
        flash("Invalid credentials ", "error")
        return redirect(url_for("receplog"))


#hospital-register
@app.route("/hos_reg_data",methods=['POST'])
def hos_reg_data():
    if request.method == "POST":
        if 'admin' in session:
            hosid = request.form['hos_id']
            name = request.form['name']
            phno = request.form['phno']
            address = request.form['address']
            id_check = Hospital.query.filter_by(hospitalid=hosid).first()
            if not id_check:
                name_check = Hospital.query.filter_by(name=name).first()
                if not name_check:
                    phno_check = Hospital.query.filter_by(phno=phno).first()
                    if not phno_check:
                        address_check = Hospital.query.filter_by(address=address).first()
                        if not address_check:
                            hash_pasw = sha256_crypt.hash(phno)
                            hospital = Hospital(hospitalid=hosid,name=name,phno=phno,address=address,password=hash_pasw)
                            db.session.add(hospital)
                            db.session.commit()
                            flash("Registration success","success")
                            return redirect(url_for("Admindash"))
                        else:
                            flash("Address already exists",'error')
                            return redirect(url_for("Hosreg"))
                    else:
                        flash("Phone number already exists", 'error')
                        return redirect(url_for("Hosreg"))
                else:
                    flash("Hospital Name already exists", 'error')
                    return redirect(url_for("Hosreg"))
            else:
                flash("ID has already been taken", 'error')
                return redirect(url_for("Hosreg"))
        flash("you are not authorized", 'error')
        return redirect(url_for("Adminlog"))

@app.route("/hos_login_data",methods=['POST'])
def hos_login_data():
    if request.method == "POST":
        hosid = request.form['hosid']
        password = request.form['password']
        response = Hospital.query.filter_by(hospitalid=hosid).first()
        if not response:
            flash("Hospital not registered",'error')
            return redirect(url_for('Hoslog'))
        else:
            checkpass = sha256_crypt.verify(password,response.password)
            if checkpass:
                session['hospital'] = True
                session['name'] = response.name
                session['hosid'] = response.hospitalid
                session['phno'] = response.phno
                session['address'] = response.address
                flash("Login Successfull",'success')
                return redirect(url_for('Hosdash'))
            else:
                flash('Invalid Credentials',"error")
                return redirect(url_for("Hoslog"))

#bloodbank registration

@app.route("/blood_bank_reg_data",methods=['POST'])
def blood_bank_reg_data():
    if request.method == 'POST':
        if 'admin' in session:
            bank_no = request.form['bank_no']
            name = request.form['name']
            phone = request.form['phone']
            address = request.form['address']
            bank_no = request.form['bank_no']
            bank_check = Blood_bank.query.filter_by(blood_bank_no=bank_no).first()
            if not bank_check:
                name_check = Blood_bank.query.filter_by(name=name).first()
                if not name_check:
                    has_pasw = sha256_crypt.hash(phone)
                    bank = Blood_bank(blood_bank_no=bank_no,name=name,phone=phone,address=address,password=has_pasw)
                    db.session.add(bank)
                    db.session.commit()
                    flash("Blood bank added successfully","success")
                    return redirect(url_for("Admindash"))
                flash("Name already taken",'error')
                return redirect(url_for("Bloodbank_reg"))
            flash("Bank No already taken", 'error')
            return redirect(url_for("Bloodbank_reg"))
        flash("you are not authorized", "error")
        return redirect(url_for("Adminlog"))

#blood bank login
@app.route("/bank_login_data",methods=['POST'])
def bank_login_data():
    if request.method == 'POST':
        bank_no = request.form['bank_no']
        pasw = request.form['pass']
        check_bank = Blood_bank.query.filter_by(blood_bank_no=bank_no).first()
        if check_bank:
            check_pass=sha256_crypt.verify(pasw,check_bank.password)
            if check_pass:
                session['blood_bank_no'] = check_bank.blood_bank_no
                session['blood_bank_name'] = check_bank.name
                session['blood_bank_phone'] = check_bank.phone
                session['blood_bank'] = True
                flash("logged in","success")
                return redirect(url_for("bloodbank_dash"))
            flash("Invalid credentials","error")
            return redirect(url_for("bloodbank_login"))
        flash("Invalid credentials", "error")
        return redirect(url_for("bloodbank_login"))

#donor details register
@app.route("/donor_data",methods=['POST'])
def donor_data():
    if request.method == 'POST':
        if 'blood_bank' in session:
            cand_no = request.form['cand_no']
            name = request.form['name']
            phone = request.form['phone']
            email = request.form['email']
            address = request.form['address']
            gender = request.form['gender']
            blood_type = request.form['types']
            check_cand_no = Donor.query.filter_by(candidate_no=cand_no).first()
            if not check_cand_no:
                check_phone = Donor.query.filter_by(phone=phone).first()
                if not check_phone:
                    check_email = Donor.query.filter_by(email=email).first()
                    if not check_email:
                        donor = Donor(candidate_no=cand_no,name=name,phone=phone,email=email,address=address,gender=gender,blood_type=blood_type,blood_bank=session['blood_bank_no'])
                        db.session.add(donor)
                        db.session.commit()
                        flash("Donor regisered successfully","success")
                        return redirect(url_for("donorform"))
                    flash("EMail already used","error")
                    return redirect(url_for("donorform"))
                flash("Phone already used", "error")
                return redirect(url_for("donorform"))
            flash("Candidate number already used", "error")
            return redirect(url_for("donorform"))
        flash("you are not authorized", "error")
        return redirect(url_for("bloodbank_login"))

#blood donation details
@app.route("/donation_data",methods=['POST'])
def donation_data():
    if request.method == 'POST':
        if 'blood_bank' in session:
            cand_no = request.form['cand_no']
            units = request.form['unit']
            blood_type = request.form['types']
            try:
                donor = Donor.query.filter_by(candidate_no=cand_no).first()
                donations = Donation(units=units,blood_type=blood_type,donor=donor,blood_bank=session['blood_bank_no'])
                db.session.add(donations)
                db.session.commit()
            except sqlalchemy.exc.IntegrityError:
                flash("Please verify candidate number", "error")
                return redirect(url_for("donordetails"))

            flash("Donation stored","success")
            return redirect(url_for("donordetails"))
        flash("you are not authorized", "error")
        return redirect(url_for("bloodbank_login"))

#receptionist password change
@app.route("/recep_changepass",methods=['POST'])
def recep_changepass():
    if 'receptionist' in session:
        if request.method == 'POST':
            email = request.form['email']
            pass1 = request.form['pass1']
            pass2 = request.form['pass2']
            if pass1 == pass2:
                check_email = Receptionist.query.filter_by(email=email).first()
                if check_email:
                    hash_pasw = sha256_crypt.hash(pass1)
                    data = Receptionist.query.filter_by(email=email).first()
                    data.password = hash_pasw
                    db.session.commit()
                    flash("Password changed successfully","success")
                    return redirect(url_for("recepdash"))
                else:
                    flash("Invalid mail ID","error")
                    return redirect(url_for("changepasswordrecep"))
            else:
                flash("Passwords dont match","error")
                return redirect(url_for("changepasswordrecep"))
    else:
        flash("Please login as a receptionist","error")
        return redirect(url_for("receplog"))

#blood bank password change
@app.route("/bankpasschange",methods=['POST'])
def bankpasschange():
    if 'blood_bank' in session:
        if request.method == 'POST':
            name = request.form['name']
            pass1 = request.form['pass1']
            pass2 = request.form['pass2']
            if pass1 == pass2:
                check_email = Blood_bank.query.filter_by(name=name).first()
                if check_email:
                    hash_pasw = sha256_crypt.hash(pass1)
                    data = Blood_bank.query.filter_by(name=name).first()
                    data.password = hash_pasw
                    db.session.commit()
                    flash("Password changed successfully","success")
                    return redirect(url_for("bloodbank_dash"))
                else:
                    flash("Invalid name","error")
                    return redirect(url_for("bankforpass"))
            else:
                flash("Passwords dont match","error")
                return redirect(url_for("bankforpass"))
    else:
        flash("Please login as a Blood bank admin","error")
        return redirect(url_for("bloodbank_login"))

#hospital password change
@app.route("/hospasschange",methods=['POST'])
def hospasschange():
    if 'hospital' in session:
        if request.method == 'POST':
            hosid = request.form['hosid']
            pass1 = request.form['pass1']
            pass2 = request.form['pass2']
            if pass1 == pass2:
                check_id = Hospital.query.filter_by(hospitalid=hosid).first()
                if check_id:
                    hash_pasw = sha256_crypt.hash(pass1)
                    data = Hospital.query.filter_by(hospitalid=hosid).first()
                    data.password = hash_pasw
                    db.session.commit()
                    flash("Password changed successfully","success")
                    return redirect(url_for("Hosdash"))
                else:
                    flash("Invalid mail ID","error")
                    return redirect(url_for("changepassword"))
            else:
                flash("Passwords dont match","error")
                return redirect(url_for("changepassword"))
    else:
        flash("Please login first","error")
        return redirect(url_for("Hoslog"))


#admin forgot password
@app.route("/fpass_admin",methods=['POST'])
def fpass_admin():
    if request.method == 'POST':
        email = request.form['email']
        pass1 = request.form['pass1']
        pass2 = request.form['pass2']
        if pass1 == pass2:
            check_email = Admin.query.filter_by(email=email).first()
            if check_email:
                hash_pasw = sha256_crypt.hash(pass1)
                data = Admin.query.filter_by(email=email).first()
                data.password = hash_pasw
                db.session.commit()
                flash("Password changed successfully","success")
                return redirect(url_for("Adminlog"))
            else:
                flash("Email ID not registered","error")
                return redirect(url_for("forgotpassword"))
        else:
            flash("Passwords dont match","error")
            return redirect(url_for("forgotpassword"))

#Blood bank forgot password
@app.route("/fpass_bank",methods=['POST'])
def fpass_bank():
    if request.method == 'POST':
        email = request.form['email']
        pass1 = request.form['pass1']
        pass2 = request.form['pass2']
        if pass1 == pass2:
            check_email = Blood_bank.query.filter_by(name=email).first()
            if check_email:
                hash_pasw = sha256_crypt.hash(pass1)
                data = Blood_bank.query.filter_by(name=email).first()
                data.password = hash_pasw
                db.session.commit()
                flash("Password changed successfully","success")
                return redirect(url_for("bloodbank_login"))
            else:
                flash("Name not registered","error")
                return redirect(url_for("fcpassword_bank"))
        else:
            flash("Passwords dont match","error")
            return redirect(url_for("fcpassword_bank"))

#hospital forgot password
@app.route("/fpass_hos",methods=['POST'])
def fpass_hos():
    if request.method == 'POST':
        hosid = request.form['hosid']
        pass1 = request.form['pass1']
        pass2 = request.form['pass2']
        if pass1 == pass2:
            check_id = Hospital.query.filter_by(hospitalid=hosid).first()
            if check_id:
                hash_pasw = sha256_crypt.hash(pass1)
                data = Hospital.query.filter_by(hospitalid=hosid).first()
                data.password = hash_pasw
                db.session.commit()
                flash("Password changed successfully","success")
                return redirect(url_for("Hoslog"))
            else:
                flash("Hospital not registered","error")
                return redirect(url_for("forgotpassword_hos"))
        else:
            flash("Passwords dont match","error")
            return redirect(url_for("forgotpassword_hos"))

#receptionist forgot password
@app.route("/fpass_recep",methods=['POST'])
def fpass_recep():
    if request.method == 'POST':
        email = request.form['email']
        pass1 = request.form['pass1']
        pass2 = request.form['pass2']
        if pass1 == pass2:
            check_email = Receptionist.query.filter_by(email=email).first()
            if check_email:
                hash_pasw = sha256_crypt.hash(pass1)
                data = Receptionist.query.filter_by(email=email).first()
                data.password = hash_pasw
                db.session.commit()
                flash("Password changed successfully","success")
                return redirect(url_for("receplog"))
            else:
                flash("Email ID not registered","error")
                return redirect(url_for("forgotpassword_recep"))
        else:
            flash("Passwords dont match","error")
            return redirect(url_for("forgotpassword_recep"))

#hospital edit
@app.route('/hos_edit/<int:id>')
def hos_edit(id):
    if 'admin' in session:
        data = Hospital.query.filter_by(hospitalid=id).first()
        return render_template('hos_edit.html',data=data)
    flash("You are not authorized to perform this action", "error")
    return redirect(url_for("Adminlog"))

#hospital delete
@app.route('/hos_del/<int:id>')
def hos_del(id):
    if 'admin' in session:
        data = Hospital.query.filter_by(hospitalid=id).first()
        db.session.delete(data)
        db.session.commit()
        flash("data deleted successfully","success")
        return redirect(url_for("Hos_list"))
    flash("You are not authorized to perform this action", "error")
    return redirect(url_for("Adminlog"))

#blood bank edit
@app.route('/blood_edit/<int:id>')
def blood_edit(id):
    if 'admin' in session:
        data = Blood_bank.query.filter_by(blood_bank_no=id).first()
        return render_template('blood_bank_edit.html',data=data)
    flash("You are not authorized to perform this action", "error")
    return redirect(url_for("Adminlog"))

#Blood bank delete
@app.route('/blood_del/<int:id>')
def blood_del(id):
    if 'admin' in session:
        data = Blood_bank.query.filter_by(blood_bank_no=id).first()
        db.session.delete(data)
        db.session.commit()
        flash("data deleted successfully","success")
        return redirect(url_for("blood_list"))
    flash("You are not authorized to perform this action", "error")
    return redirect(url_for("Adminlog"))

#receptionist edit
@app.route('/recep_edit/<int:id>')
def recep_edit(id):
    if 'admin' in session:
        data = Receptionist.query.filter_by(id=id).first()
        return render_template('recep_edit.html',data=data)
    flash("You are not authorized to perform this action", "error")
    return redirect(url_for("Adminlog"))

#receptionist delete
@app.route('/recep_del/<int:id>')
def recep_del(id):
    if 'admin' in session:
        data = Receptionist.query.filter_by(id=id).first()
        db.session.delete(data)
        db.session.commit()
        flash("data deleted successfully","success")
        return redirect(url_for("Recep_list"))
    flash("You are not authorized to perform this action", "error")
    return redirect(url_for("Adminlog"))


#donor edit
@app.route('/donor_edit/<int:id>')
def donor_edit(id):
    if 'admin' in session:
        data = Donor.query.filter_by(candidate_no=id).first()
        return render_template('donor_edit.html',data=data)
    flash("You are not authorized to perform this action", "error")
    return redirect(url_for("Adminlog"))

#Donor delete
@app.route('/donor_del/<int:id>')
def donor_del(id):
    if 'admin' in session:
        data = Donor.query.filter_by(candidate_no=id).first()
        db.session.delete(data)
        db.session.commit()
        flash("data deleted successfully","success")
        return redirect(url_for("donor_list"))
    flash("You are not authorized to perform this action", "error")
    return redirect(url_for("Adminlog"))


#donation edit
@app.route('/donation_edit/<int:id>')
def donation_edit(id):
    if 'admin' in session:
        data = Donation.query.filter_by(id=id).first()
        return render_template('donation_edit.html',data=data)
    flash("You are not authorized to perform this action", "error")
    return redirect(url_for("Adminlog"))

#Donation delete
@app.route('/donation_del/<int:id>')
def donation_del(id):
    if 'admin' in session:
        data = Donation.query.filter_by(id=id).first()
        db.session.delete(data)
        db.session.commit()
        flash("data deleted successfully","success")
        return redirect(url_for("donor_list1"))
    flash("You are not authorized to perform this action","error")
    return redirect(url_for("Adminlog"))


@app.route("/hos_edit_data/<int:id>",methods=['POST'])
def hos_edit_data(id):
    if 'admin' in session:
        if request.method == "POST":
            name = request.form['name']
            phno = request.form['phno']
            address = request.form['address']
            data = Hospital.query.filter_by(hospitalid=id).first()
            name_check = Hospital.query.filter_by(name=name).first()
            if name_check:
                if(name_check.hospitalid != id):
                    flash("Hospital name already used","error")
                    data = Hospital.query.filter_by(hospitalid=id).first()
                    return render_template('hos_edit.html',data=data)
                elif(name_check.hospitalid == id):
                    data.name = name
                    phno_check = Hospital.query.filter_by(phno=phno).first()
                    if phno_check:
                        if(phno_check.hospitalid != id):
                            flash("Phone number already used","error")
                            data = Hospital.query.filter_by(hospitalid=id).first()
                            return render_template('hos_edit.html',data=data)
                        elif(phno_check.hospitalid == id):
                            data.phno = phno
                            address_check = Hospital.query.filter_by(address=address).first()
                            if address_check:
                                if(address_check.hospitalid != id):
                                    flash("Address already used","error")
                                    data = Hospital.query.filter_by(hospitalid=id).first()
                                    return render_template('hos_edit.html',data=data)
                                elif(address_check.hospitalid == id):
                                    data.address = address
                                    db.session.commit()
                                    flash("Hospital details updated successfully","success")
                                    return redirect(url_for("Hos_list"))
                            else:
                                data.address = address
                                db.session.commit()
                                flash("Hospital details updated successfully","success")
                                return redirect(url_for("Hos_list"))
                    else:
                        data.phno = phno
                        address_check = Hospital.query.filter_by(address=address).first()
                        if address_check:
                            if(address_check.hospitalid != id):
                                flash("Address already used","error")
                                data = Hospital.query.filter_by(hospitalid=id).first()
                                return render_template('hos_edit.html',data=data)
                            elif(address_check.hospitalid == id):
                                data.address = address
                                db.session.commit()
                                flash("Hospital details updated successfully","success")
                                return redirect(url_for("Hos_list"))
                        else:
                            data.address = address
                            db.session.commit()
                            flash("Hospital details updated successfully","success")
                            return redirect(url_for("Hos_list"))
            else:
                data.name = name
                phno_check = Hospital.query.filter_by(phno=phno).first()
                if phno_check:
                    if(phno_check.hospitalid != id):
                        flash("Phone number already used","error")
                        data = Hospital.query.filter_by(hospitalid=id).first()
                        return render_template('hos_edit.html',data=data)
                    elif(phno_check.hospitalid == id):
                        data.phno = phno
                        address_check = Hospital.query.filter_by(address=address).first()
                        if address_check:
                            if(address_check.hospitalid != id):
                                flash("Address already used","error")
                                data = Hospital.query.filter_by(hospitalid=id).first()
                                return render_template('hos_edit.html',data=data)
                            elif(address_check.hospitalid == id):
                                data.address = address
                                db.session.commit()
                                flash("Hospital details updated successfully","success")
                                return redirect(url_for("Hos_list"))
                        else:
                            data.address = address
                            db.session.commit()
                            flash("Hospital details updated successfully","success")
                            return redirect(url_for("Hos_list"))
                else:
                    data.phno = phno
                    address_check = Hospital.query.filter_by(address=address).first()
                    if address_check:
                        if(address_check.hospitalid != id):
                            flash("Address already used","error")
                            data = Hospital.query.filter_by(hospitalid=id).first()
                            return render_template('hos_edit.html',data=data)
                        elif(address_check.hospitalid == id):
                            data.address = address
                            db.session.commit()
                            flash("Hospital details updated successfully","success")
                            return redirect(url_for("Hos_list"))
                    else:
                        data.address = address
                        db.session.commit()
                        flash("Hospital details updated successfully","success")
                        return redirect(url_for("Hos_list"))
    else:
        flash("Please login as a admin","error")
        return redirect(url_for("Adminlog"))


@app.route("/blood_bank_edit_data/<int:id>",methods=['POST'])
def blood_bank_edit_data(id):
    if 'admin' in session:
        if request.method == "POST":
            name = request.form['name']
            phno = request.form['phno']
            address = request.form['address']
            data = Blood_bank.query.filter_by(blood_bank_no=id).first()
            name_check = Blood_bank.query.filter_by(name=name).first()
            if name_check:
                if(name_check.blood_bank_no != id):
                    flash("Blood Bank name already used","error")
                    data = Blood_bank.query.filter_by(blood_bank_no=id).first()
                    return render_template('blood_bank_edit.html',data=data)
                elif(name_check.blood_bank_no == id):
                    data.name = name
                    phno_check = Blood_bank.query.filter_by(phone=phno).first()
                    if phno_check:
                        if(phno_check.blood_bank_no != id):
                            flash("Phone number already used","error")
                            data = Blood_bank.query.filter_by(blood_bank_no=id).first()
                            return render_template('blood_bank_edit.html',data=data)
                        elif(phno_check.blood_bank_no == id):
                            data.phone = phno
                            address_check = Blood_bank.query.filter_by(address=address).first()
                            if address_check:
                                if(address_check.blood_bank_no != id):
                                    flash("Address already used","error")
                                    data = Blood_bank.query.filter_by(blood_bank_no=id).first()
                                    return render_template('blood_bank_edit.html',data=data)
                                elif(address_check.blood_bank_no == id):
                                    data.address = address
                                    db.session.commit()
                                    flash("Blood bank details updated successfully","success")
                                    return redirect(url_for("blood_list"))
                            else:
                                data.address = address
                                db.session.commit()
                                flash("Blood bank details updated successfully","success")
                                return redirect(url_for("blood_list"))
                    else:
                        data.phone = phno
                        address_check = Blood_bank.query.filter_by(address=address).first()
                        if address_check:
                            if(address_check.blood_bank_no != id):
                                flash("Address already used","error")
                                data = Blood_bank.query.filter_by(blood_bank_no=id).first()
                                return render_template('blood_bank_edit.html',data=data)
                            elif(address_check.blood_bank_no == id):
                                data.address = address
                                db.session.commit()
                                flash("Blood bank details updated successfully","success")
                                return redirect(url_for("blood_list"))
                        else:
                            data.address = address
                            db.session.commit()
                            flash("Blood bank details updated successfully","success")
                            return redirect(url_for("blood_list"))
            else:
                data.name = name
                phno_check = Blood_bank.query.filter_by(phone=phno).first()
                if phno_check:
                    if(phno_check.blood_bank_no != id):
                        flash("Phone number already used","error")
                        data = Blood_bank.query.filter_by(blood_bank_no=id).first()
                        return render_template('blood_bank_edit.html',data=data)
                    elif(phno_check.blood_bank_no == id):
                        data.phone = phno
                        address_check = Blood_bank.query.filter_by(address=address).first()
                        if address_check:
                            if(address_check.blood_bank_no != id):
                                flash("Address already used","error")
                                data = Blood_bank.query.filter_by(blood_bank_no=id).first()
                                return render_template('blood_bank_edit.html',data=data)
                            elif(address_check.blood_bank_no == id):
                                data.address = address
                                db.session.commit()
                                flash("Blood bank details updated successfully","success")
                                return redirect(url_for("blood_list"))
                        else:
                            data.address = address
                            db.session.commit()
                            flash("Blood bank details updated successfully","success")
                            return redirect(url_for("blood_list"))
                else:
                    data.phone = phno
                    address_check = Blood_bank.query.filter_by(address=address).first()
                    if address_check:
                        if(address_check.blood_bank_no != id):
                            flash("Address already used","error")
                            data = Blood_bank.query.filter_by(blood_bank_no=id).first()
                            return render_template('blood_bank_edit.html',data=data)
                        elif(address_check.blood_bank_no == id):
                            data.address = address
                            db.session.commit()
                            flash("Blood bank details updated successfully","success")
                            return redirect(url_for("blood_list"))
                    else:
                        data.address = address
                        db.session.commit()
                        flash("Blood bank details updated successfully","success")
                        return redirect(url_for("blood_list"))
    else:
        flash("Please login as a admin","error")
        return redirect(url_for("Adminlog"))

@app.route("/recep_edit_data/<int:id>",methods=['POST'])
def recep_edit_data(id):
    if 'admin' in session:
        if request.method == "POST":
            name = request.form['name']
            mail = request.form['email']
            phno = request.form['phno']
            address = request.form['address']
            data = Receptionist.query.filter_by(id=id).first()
            name_check = Receptionist.query.filter_by(name=name).first()
            if name_check:
                if(name_check.id != id):
                    flash("Receptionist name already used","error")
                    data = Receptionist.query.filter_by(id=id).first()
                    return render_template('recep_edit.html',data=data)
                elif(name_check.id == id):
                    data.name = name
                    email_check = Receptionist.query.filter_by(email=mail).first()
                    if email_check:
                        if(email_check.id != id):
                            flash("Mail ID already used","error")
                            data = Receptionist.query.filter_by(id=id).first()
                            return render_template('recep_edit.html',data=data)
                        elif(email_check.id == id):
                            data.email = mail
                            phno_check = Receptionist.query.filter_by(phone=phno).first()
                            if phno_check:
                                if(phno_check.id != id):
                                    flash("Phone number already used","error")
                                    data = Receptionist.query.filter_by(id=id).first()
                                    return render_template('recep_edit.html',data=data)
                                elif(phno_check.id == id):
                                    data.phone = phno
                                    address_check = Receptionist.query.filter_by(address=address).first()
                                    if address_check:
                                        if(address_check.id != id):
                                            flash("Address already used","error")
                                            data = Receptionist.query.filter_by(id=id).first()
                                            return render_template('recep_edit.html',data=data)
                                        elif(address_check.id == id):
                                            data.address = address
                                            db.session.commit()
                                            flash("Receptionist details updated successfully","success")
                                            return redirect(url_for("Recep_list"))
                                    else:
                                        data.address = address
                                        db.session.commit()
                                        flash("Receptionist details updated successfully","success")
                                        return redirect(url_for("Recep_list"))
                            else:
                                data.phone = phno
                                address_check = Receptionist.query.filter_by(address=address).first()
                                if address_check:
                                    if(address_check.id != id):
                                        flash("Address already used","error")
                                        data = Receptionist.query.filter_by(id=id).first()
                                        return render_template('recep_edit.html',data=data)
                                    elif(address_check.id == id):
                                        data.address = address
                                        db.session.commit()
                                        flash("Receptionist details updated successfully","success")
                                        return redirect(url_for("Recep_list"))
                                else:
                                    data.address = address
                                    db.session.commit()
                                    flash("Receptionist details updated successfully","success")
                                    return redirect(url_for("Recep_list"))
                    else:
                        data.email = mail
                        phno_check = Receptionist.query.filter_by(phone=phno).first()
                        if phno_check:
                            if(phno_check.id != id):
                                flash("Phone number already used","error")
                                data = Receptionist.query.filter_by(id=id).first()
                                return render_template('recep_edit.html',data=data)
                            elif(phno_check.id == id):
                                data.phone = phno
                                address_check = Receptionist.query.filter_by(address=address).first()
                                if address_check:
                                    if(address_check.id != id):
                                        flash("Address already used","error")
                                        data = Receptionist.query.filter_by(id=id).first()
                                        return render_template('recep_edit.html',data=data)
                                    elif(address_check.id == id):
                                        data.address = address
                                        db.session.commit()
                                        flash("Receptionist details updated successfully","success")
                                        return redirect(url_for("Recep_list"))
                                else:
                                    data.address = address
                                    db.session.commit()
                                    flash("Receptionist details updated successfully","success")
                                    return redirect(url_for("Recep_list"))
                        else:
                            data.phone = phno
                            address_check = Receptionist.query.filter_by(address=address).first()
                            if address_check:
                                if(address_check.id != id):
                                    flash("Address already used","error")
                                    data = Receptionist.query.filter_by(id=id).first()
                                    return render_template('recep_edit.html',data=data)
                                elif(address_check.id == id):
                                    data.address = address
                                    db.session.commit()
                                    flash("Receptionist details updated successfully","success")
                                    return redirect(url_for("Recep_list"))
                            else:
                                data.address = address
                                db.session.commit()
                                flash("Receptionist details updated successfully","success")
                                return redirect(url_for("Recep_list"))
            else:
                data.name = name
                email_check = Receptionist.query.filter_by(email=mail).first()
                if email_check:
                    if(email_check.id != id):
                        flash("Mail ID already used","error")
                        data = Receptionist.query.filter_by(id=id).first()
                        return render_template('recep_edit.html',data=data)
                    elif(email_check.id == id):
                        data.email = mail
                        phno_check = Receptionist.query.filter_by(phone=phno).first()
                        if phno_check:
                            if(phno_check.id != id):
                                flash("Phone number already used","error")
                                data = Receptionist.query.filter_by(id=id).first()
                                return render_template('recep_edit.html',data=data)
                            elif(phno_check.id == id):
                                data.phone = phno
                                address_check = Receptionist.query.filter_by(address=address).first()
                                if address_check:
                                    if(address_check.id != id):
                                        flash("Address already used","error")
                                        data = Receptionist.query.filter_by(id=id).first()
                                        return render_template('recep_edit.html',data=data)
                                    elif(address_check.id == id):
                                        data.address = address
                                        db.session.commit()
                                        flash("Receptionist details updated successfully","success")
                                        return redirect(url_for("Recep_list"))
                                else:
                                    data.address = address
                                    db.session.commit()
                                    flash("Receptionist details updated successfully","success")
                                    return redirect(url_for("Recep_list"))
                        else:
                            data.phone = phno
                            address_check = Receptionist.query.filter_by(address=address).first()
                            if address_check:
                                if(address_check.id != id):
                                    flash("Address already used","error")
                                    data = Receptionist.query.filter_by(id=id).first()
                                    return render_template('recep_edit.html',data=data)
                                elif(address_check.id == id):
                                    data.address = address
                                    db.session.commit()
                                    flash("Receptionist details updated successfully","success")
                                    return redirect(url_for("Recep_list"))
                            else:
                                data.address = address
                                db.session.commit()
                                flash("Receptionist details updated successfully","success")
                                return redirect(url_for("Recep_list"))
                else:
                    data.email = mail
                    phno_check = Receptionist.query.filter_by(phone=phno).first()
                    if phno_check:
                        if(phno_check.id != id):
                            flash("Phone number already used","error")
                            data = Receptionist.query.filter_by(id=id).first()
                            return render_template('recep_edit.html',data=data)
                        elif(phno_check.id == id):
                            data.phone = phno
                            address_check = Receptionist.query.filter_by(address=address).first()
                            if address_check:
                                if(address_check.id != id):
                                    flash("Address already used","error")
                                    data = Receptionist.query.filter_by(id=id).first()
                                    return render_template('recep_edit.html',data=data)
                                elif(address_check.id == id):
                                    data.address = address
                                    db.session.commit()
                                    flash("Receptionist details updated successfully","success")
                                    return redirect(url_for("Recep_list"))
                            else:
                                data.address = address
                                db.session.commit()
                                flash("Receptionist details updated successfully","success")
                                return redirect(url_for("Recep_list"))
                    else:
                        data.phone = phno
                        address_check = Receptionist.query.filter_by(address=address).first()
                        if address_check:
                            if(address_check.id != id):
                                flash("Address already used","error")
                                data = Receptionist.query.filter_by(id=id).first()
                                return render_template('recep_edit.html',data=data)
                            elif(address_check.id == id):
                                data.address = address
                                db.session.commit()
                                flash("Receptionist details updated successfully","success")
                                return redirect(url_for("Recep_list"))
                        else:
                            data.address = address
                            db.session.commit()
                            flash("Receptionist details updated successfully","success")
                            return redirect(url_for("Recep_list"))
                if not name_check and not phno_check and not email_check:
                    data.name = name
                    data.phone = phno
                    data.email = mail
                    address_check = Receptionist.query.filter_by(address=address).first()
                    if address_check:
                        if(address_check.id != id):
                            flash("Address already used","error")
                            data = Receptionist.query.filter_by(id=id).first()
                            return render_template('recep_edit.html',data=data)
                        elif(address_check.id == id):
                            data.address = address
                            db.session.commit()
                            flash("Receptionist details updated successfully","success")
                            return redirect(url_for("Recep_list"))
                    else:
                        data.address = address
                        db.session.commit()
                        flash("Receptionist details updated successfully","success")
                        return redirect(url_for("Recep_list"))
    else:
        flash("Please login as a admin","error")
        return redirect(url_for("Adminlog"))

@app.route("/donor_edit_data/<int:id>",methods=['POST'])
def donor_edit_data(id):
    if 'admin' in session:
        if request.method == "POST":
            name = request.form['name']
            mail = request.form['email']
            phno = request.form['phno']
            address = request.form['address']
            btype = request.form['types']
            data = Donor.query.filter_by(candidate_no=id).first()
            name_check = Donor.query.filter_by(name=name).first()
            if name_check:
                if(name_check.candidate_no != id):
                    flash("Blood Bank name already used","error")
                    data = Donor.query.filter_by(candidate_no=id).first()
                    return render_template('donor_edit.html',data=data)
                elif(name_check.candidate_no == id):
                    data.name = name
                    email_check = Donor.query.filter_by(email=mail).first()
                    if email_check:
                        if(email_check.candidate_no != id):
                            flash("Mail ID already used","error")
                            data = Donor.query.filter_by(candidate_no=id).first()
                            return render_template('donor_edit.html',data=data)
                        elif(email_check.candidate_no == id):
                            data.email = mail
                            phno_check = Donor.query.filter_by(phone=phno).first()
                            if phno_check:
                                if(phno_check.candidate_no != id):
                                    flash("Phone number already used","error")
                                    data = Donor.query.filter_by(candidate_no=id).first()
                                    return render_template('donor_edit.html',data=data)
                                elif(phno_check.candidate_no == id):
                                    data.phone = phno
                                    address_check = Donor.query.filter_by(address=address).first()
                                    if address_check:
                                        if(address_check.candidate_no != id):
                                            flash("Address already used","error")
                                            data = Donor.query.filter_by(candidate_no=id).first()
                                            return render_template('donor_edit.html',data=data)
                                        elif(address_check.candidate_no == id):
                                            data.address = address
                                            data.blood_type = btype
                                            db.session.commit()
                                            flash("Donor details updated successfully","success")
                                            return redirect(url_for("donor_list"))
                                    else:
                                        data.address = address
                                        data.blood_type = btype
                                        db.session.commit()
                                        flash("Donor details updated successfully","success")
                                        return redirect(url_for("donor_list"))
                            else:
                                data.phone = phno
                                address_check = Donor.query.filter_by(address=address).first()
                                if address_check:
                                    if(address_check.candidate_no != id):
                                        flash("Address already used","error")
                                        data = Donor.query.filter_by(candidate_no=id).first()
                                        return render_template('donor_edit.html',data=data)
                                    elif(address_check.candidate_no == id):
                                        data.address = address
                                        data.blood_type = btype
                                        db.session.commit()
                                        flash("Donor details updated successfully","success")
                                        return redirect(url_for("donor_list"))
                                else:
                                    data.address = address
                                    data.blood_type = btype
                                    db.session.commit()
                                    flash("Donor details updated successfully","success")
                                    return redirect(url_for("donor_list"))
                    else:
                        data.email = mail
                        phno_check = Donor.query.filter_by(phone=phno).first()
                        if phno_check:
                            if(phno_check.candidate_no != id):
                                flash("Phone number already used","error")
                                data = Donor.query.filter_by(candidate_no=id).first()
                                return render_template('donor_edit.html',data=data)
                            elif(phno_check.candidate_no == id):
                                data.phone = phno
                                address_check = Donor.query.filter_by(address=address).first()
                                if address_check:
                                    if(address_check.candidate_no != id):
                                        flash("Address already used","error")
                                        data = Donor.query.filter_by(candidate_no=id).first()
                                        return render_template('donor_edit.html',data=data)
                                    elif(address_check.candidate_no == id):
                                        data.address = address
                                        data.blood_type = btype
                                        db.session.commit()
                                        flash("Donor details updated successfully","success")
                                        return redirect(url_for("donor_list"))
                                else:
                                    data.address = address
                                    data.blood_type = btype
                                    db.session.commit()
                                    flash("Donor details updated successfully","success")
                                    return redirect(url_for("donor_list"))
                        else:
                            data.phone = phno
                            address_check = Donor.query.filter_by(address=address).first()
                            if address_check:
                                if(address_check.candidate_no != id):
                                    flash("Address already used","error")
                                    data = Donor.query.filter_by(candidate_no=id).first()
                                    return render_template('donor_edit.html',data=data)
                                elif(address_check.candidate_no == id):
                                    data.address = address
                                    data.blood_type = btype
                                    db.session.commit()
                                    flash("Donor details updated successfully","success")
                                    return redirect(url_for("donor_list"))
                            else:
                                data.address = address
                                data.blood_type = btype
                                db.session.commit()
                                flash("Donor details updated successfully","success")
                                return redirect(url_for("donor_list"))
            else:
                data.name = name
                email_check = Donor.query.filter_by(email=mail).first()
                if email_check:
                    if(email_check.candidate_no != id):
                        flash("Mail ID already used","error")
                        data = Donor.query.filter_by(candidate_no=id).first()
                        return render_template('donor_edit.html',data=data)
                    elif(email_check.candidate_no == id):
                        data.email = mail
                        phno_check = Donor.query.filter_by(phone=phno).first()
                        if phno_check:
                            if(phno_check.candidate_no != id):
                                flash("Phone number already used","error")
                                data = Donor.query.filter_by(candidate_no=id).first()
                                return render_template('donor_edit.html',data=data)
                            elif(phno_check.candidate_no == id):
                                data.phone = phno
                                address_check = Donor.query.filter_by(address=address).first()
                                if address_check:
                                    if(address_check.candidate_no != id):
                                        flash("Address already used","error")
                                        data = Donor.query.filter_by(candidate_no=id).first()
                                        return render_template('donor_edit.html',data=data)
                                    elif(address_check.candidate_no == id):
                                        data.address = address
                                        data.blood_type = btype
                                        db.session.commit()
                                        flash("Donor details updated successfully","success")
                                        return redirect(url_for("donor_list"))
                                else:
                                    data.address = address
                                    data.blood_type = btype
                                    db.session.commit()
                                    flash("Donor details updated successfully","success")
                                    return redirect(url_for("donor_list"))
                        else:
                            data.phone = phno
                            address_check = Donor.query.filter_by(address=address).first()
                            if address_check:
                                if(address_check.candidate_no != id):
                                    flash("Address already used","error")
                                    data = Donor.query.filter_by(candidate_no=id).first()
                                    return render_template('donor_edit.html',data=data)
                                elif(address_check.candidate_no == id):
                                    data.address = address
                                    data.blood_type = btype
                                    db.session.commit()
                                    flash("Donor details updated successfully","success")
                                    return redirect(url_for("donor_list"))
                            else:
                                data.address = address
                                data.blood_type = btype
                                db.session.commit()
                                flash("Donor details updated successfully","success")
                                return redirect(url_for("donor_list"))
                else:
                    data.email = mail
                    phno_check = Donor.query.filter_by(phone=phno).first()
                    if phno_check:
                        if(phno_check.candidate_no != id):
                            flash("Phone number already used","error")
                            data = Donor.query.filter_by(candidate_no=id).first()
                            return render_template('donor_edit.html',data=data)
                        elif(phno_check.candidate_no == id):
                            data.phone = phno
                            address_check = Donor.query.filter_by(address=address).first()
                            if address_check:
                                if(address_check.candidate_no != id):
                                    flash("Address already used","error")
                                    data = Donor.query.filter_by(candidate_no=id).first()
                                    return render_template('donor_edit.html',data=data)
                                elif(address_check.candidate_no == id):
                                    data.address = address
                                    data.blood_type = btype
                                    db.session.commit()
                                    flash("Donor details updated successfully","success")
                                    return redirect(url_for("donor_list"))
                            else:
                                data.address = address
                                data.blood_type = btype
                                db.session.commit()
                                flash("Donor details updated successfully","success")
                                return redirect(url_for("donor_list"))
                    else:
                        data.phone = phno
                        address_check = Donor.query.filter_by(address=address).first()
                        if address_check:
                            if(address_check.candidate_no != id):
                                flash("Address already used","error")
                                data = Donor.query.filter_by(candidate_no=id).first()
                                return render_template('donor_edit.html',data=data)
                            elif(address_check.candidate_no == id):
                                data.address = address
                                data.blood_type = btype
                                db.session.commit()
                                flash("Donor details updated successfully","success")
                                return redirect(url_for("donor_list"))
                        else:
                            data.address = address
                            data.blood_type = btype
                            db.session.commit()
                            flash("Donor details updated successfully","success")
                            return redirect(url_for("donor_list"))
                if not name_check and not phno_check and not email_check:
                    data.name = name
                    data.phone = phno
                    data.email = mail
                    address_check = Donor.query.filter_by(address=address).first()
                    if address_check:
                        if(address_check.candidate_no != id):
                            flash("Address already used","error")
                            data = Donor.query.filter_by(candidate_no=id).first()
                            return render_template('donor_edit.html',data=data)
                        elif(address_check.candidate_no == id):
                            data.address = address
                            data.blood_type = btype
                            db.session.commit()
                            flash("Donor details updated successfully","success")
                            return redirect(url_for("donor_list"))
                    else:
                        data.address = address
                        data.blood_type = btype
                        db.session.commit()
                        flash("Donor details updated successfully","success")
                        return redirect(url_for("donor_list"))
    else:
        flash("Please login as a admin","error")
        return redirect(url_for("Adminlog"))

@app.route("/donation_update_data/<int:id>",methods=['POST'])
def donation_update_data(id):
    if 'admin' in session:
        if request.method == "POST":
            cand_no = request.form['cand_no']
            units = request.form['unit']
            blood_type = request.form['types']
            donor = Donor.query.filter_by(candidate_no=cand_no).first()
            donations = Donation(units=units,blood_type=blood_type,donor=donor)
            db.session.add(donations)
            db.session.commit()
            flash("Details updated successfully","success")
            return redirect(url_for("Admindash"))
    else:
        flash("Please login as a admin","error")
        return redirect(url_for("Adminlog"))

@app.route("/check_orders/<int:id>")
def check_orders(id):
    # name = Donor.query.filter_by(candidate_no=123).first()
    # print(name.Donations)
    v = db.session.query(func.sum(Donation.units), Donation.blood_type).group_by(Donation.blood_type).filter(Donation.blood_bank == id)
    return render_template("check__order.html",data=v)




if __name__ == '__main__':
    app.run(debug=True) 
