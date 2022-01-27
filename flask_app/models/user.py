import flask_app
from flask_app.config.mysqlconnection import connectToMySQL # imports database info
from flask import flash # able to use flash messages
from flask_bcrypt import Bcrypt
from flask_app import app
import re # imports compile to check email
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') # email format
bcrypt = Bcrypt(app)

class User:
    def __init__(self, data): # data is a dictionary that holds the data from the database
        self.id = data["id"]
        self.first_name = data["first_name"]
        self.last_name = data["last_name"]
        self.email = data["email"]
        self.password = data["password"]
        self.confirm_password = data["confirm_password"]
        self.created_at = data["created_at"]
        self.updated_at = data["updated_at"]

    @classmethod # CREATE
    def create(cls, data):
        query = "INSERT INTO users (first_name, last_name, email, password, confirm_password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, %(confirm_password)s, NOW(), NOW());"
        result = connectToMySQL("login_and_registration_schema").query_db(query, data)
        return result 
    
    @classmethod # READ ONE
    def get_one(cls, data):
        query = "SELECT * FROM users WHERE id = %(id)s;"
        result = connectToMySQL("login_and_registration_schema").query_db(query, data)
        return cls(result[0])
    
    @classmethod # GET EMAIL
    def get_by_email(cls, data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        result = connectToMySQL("login_and_registration_schema").query_db(query, data)
        if len(result) < 1: # if there is no user with this email then return false
            return False
        
        return cls(result[0])
    
    @classmethod # GET ID
    def get_by_id(cls, data):
        query = "SELECT * FROM users WHERE id = %(id)s;"
        result = connectToMySQL("login_and_registration_schema").query_db(query, data)
        return cls(result[0])

    @classmethod # READ ALL
    def get_all(cls):
        query = "SELECT * FROM users;"
        result = connectToMySQL("login_and_registration_schema").query_db(query)
        users = []
        for row in result:
            users.append(cls(row))
        return users

    @classmethod # UPDATE
    def update(cls, data):
        query = "UPDATE users SET first_name = %(first_name)s last_name = %(last_name)s, email = %(email)s, password = %(password)s, confirm_password = %(confirm_password)s, created_at = NOW(), updated_at = NOW() WHERE id = %(id)s;"
        return connectToMySQL("login_and_registration_schema").query_db(query, data)
    
    @classmethod # DELETE
    def destroy(cls, data):
        query = "DELETE FROM users WHERE id = %(id)s;"
        connectToMySQL("login_and_registration_schema").query_db(query, data)

    @staticmethod # REGISTER VALIDATOR
    def validator(register):
        is_valid = True
        if not EMAIL_REGEX.match(register["email"]): # validate the email address
            flash("Please enter a valid email adress")
            is_valid = False
        if len(register["first_name"]) < 3: # validates the first name
            flash("Please enter a valid first name")
            is_valid = False 
        if len(register["last_name"]) < 3: # validates the last name
            flash("Please enter a valid last name")
            is_valid = False 
        if len(register["password"]) < 6: # validates the password
            flash("Please enter a password longer than 6 characters")
            is_valid = False
        if len(register["confirm_password"]) < 6: # validates the confirm password
            flash("Please enter a password longer than 6 characters")
            is_valid = False
        if register["password"] != register["confirm_password"]: # validates if both passwords entered match
            flash("Your password and confirm password do not match")
            is_valid = False
        return is_valid 

    @staticmethod # LOG IN VALIDATOR
    def login_validator(post_data):
        is_valid = True
        user = User.get_by_email({"email": post_data["email"]})
        if not user: # checks email    checks to see if the variable is false which uses the if statement in 'get_by_email" to see if the email exists in the database
            flash("The email does not exist")
            return False
        if not bcrypt.check_password_hash(user.password, post_data["password"]): # checks password    hashes the password entered and compares it the hashed password in the database
            flash("Incorrect password")
            return False
        return is_valid 