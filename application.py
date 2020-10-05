import os
import datetime

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():

    """Show portfolio of stocks"""
    rows = db.execute("SELECT name, symbol, SUM(amount) as shares, share_price FROM purchases WHERE id = :user_id GROUP BY symbol HAVING shares > 0", user_id=session["user_id"])

    cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    cashb = float(cash[0]["cash"])

    cashf = cashb

    transactions_info = []

    for transaction_info in rows:
        symbol = str(transaction_info["symbol"])
        shares = int(transaction_info["shares"])
        quote = lookup(symbol)
        price = float(quote['price'])
        total_value_share = float(price * shares)
        cashf += total_value_share
        transactions_info.append(transaction_info)

    return render_template("index.html", rows=rows, transactions_info=transactions_info, cashf=cashf, cashb=cashb)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        stock_info = request.form.get("symbol")

        if not request.form.get("symbol") or stock_info == None:
            return apology("invalid or empty symbol", 400)
        if not request.form.get("shares") or (int(request.form.get("shares")) < 1):
            return apology("Must be a number greater than 0", 400)


        stock = stock_info.upper()
        number = int(request.form.get("shares"))
        rquote = lookup(request.form.get("symbol"))
        if (rquote == None):
                return apology("Invalid symbol", 400)

        share = db.execute("SELECT SUM(amount) as amount FROM purchases WHERE id = :id AND symbol = :symbol GROUP BY symbol", id = session["user_id"], symbol=request.form.get("symbol"))

        rows = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])

        cash = float(rows[0]["cash"])
        rquotev = float(rquote["price"])
        name = rquote["name"]

        if ((rquotev * number) > cash):
            return apology("Not enough funds", 400)
        else:
            now = datetime.datetime.now()
            time = now.strftime("%d/%m/%Y %H:%M:%S")
            db.execute("INSERT INTO purchases (id, name, symbol, amount, share_price, time) VALUES (?, ?, ?, ?, ?, ?)", (session["user_id"], name, stock, number, rquote["price"], time))
            spent = rquotev * number
            db.execute("UPDATE users SET cash = cash - :price WHERE id = :user_id", price=spent, user_id=session["user_id"])

            flash("Bought!")

            return redirect("/")
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    #Select all informatio from current user
    rows = db.execute("SELECT * FROM purchases WHERE id=:id", id = session["user_id"])

    #Set an empty array
    history = []

    #Iteract through all information from current user and store them in the array
    for row in rows:
        history.append(rows)

    return render_template("history.html", rows=rows, history=history)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        if (quote == None):
            return apology("invalid symbol", 400)
        return render_template("quoted.html", quote=quote)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    if request.method == "GET":
        return render_template("register.html")
    else:
        if not request.form.get("username"):
            return apology("Type an username", 401)

        elif not request.form.get("password"):
            return apology("Type a password", 401)

        elif not request.form.get("confirmation"):
            return apology("Must check password!", 401)

        elif (request.form.get("password") != request.form.get("confirmation")):
                return apology("passwords do not match, try again!", 401)

        add  = db.execute("SELECT * FROM users WHERE username = :user", user = request.form.get("username"))

        if len(add) == 0:
            db.execute("INSERT INTO users (username, hash) VALUES (:user, :password)", user = request.form.get("username"), password = generate_password_hash((request.form.get("password"))))

            users_row=db.execute("SELECT id FROM users WHERE username = :user", user = request.form.get("username"))

            session["user_id"] = users_row[0]["id"]

            return redirect ("/")

        else:
            return apology("Username taken. Try another one.", 401)
    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        stock_info = request.form.get("symbol")
        #Turn the information to CAPS if needed
        stock2 = stock_info.upper()
        stock = lookup(stock2)
        number = int(request.form.get("shares"))

        if not request.form.get("symbol") or stock_info == None:
            return apology("invalid or empty symbol", 400)
        if not request.form.get("shares") or (int(request.form.get("shares")) < 1):
            return apology("Must be a number greater than 0", 400)


        info = db.execute("SELECT SUM(amount) as amount FROM purchases WHERE id=:id AND symbol=:symbol GROUP BY symbol",
                          id = session["user_id"], symbol=stock["symbol"])

        if info[0]["amount"] <= 0 or info[0]["amount"] < number:
            return apology("You don't have this much shares to sell!", 400)

        #Select cash from current user
        rows = db.execute("SELECT cash FROM users WHERE id = :id", id = session["user_id"])

        cash_balance = rows[0]["cash"]
        share_price = stock["price"]

        #Check the total earned with the sell to update user balance
        total = share_price * number
        now = datetime.datetime.now()
        time = now.strftime("%d/%m/%Y %H:%M:%S")

        #Update user cash balance and insert transactions made
        db.execute("UPDATE users SET cash = cash + :price WHERE id = :id", price=total, id=session["user_id"])
        db.execute("INSERT INTO purchases (id, name, symbol, amount, share_price, time) VALUES (?, ?, ?, ?, ?, ?)",
                   (session["user_id"], stock["name"], stock["symbol"], -number, stock["price"], time))

        flash("Sold!")
        return redirect("/")
    else:
        stocks=db.execute("SELECT symbol, SUM(amount) as amount FROM purchases WHERE id=:id GROUP BY symbol HAVING amount > 0", id = session["user_id"])
        return render_template("sell.html", stocks=stocks)

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change Password"""

    if request.method == "POST":
        current = request.form.get("current")

        #Get current user's password
        hash = db.execute("SELECT hash FROM users WHERE id=:id", id=session["user_id"])

        #Check if password field is empty and if the password typed is not correct
        if not current or not check_password_hash(hash[0]["hash"], current):
            return apology("Current password field empty or invalid")

        #If password is correct:
        else:
            new = (request.form.get("newp"))
            if new == None:
                return apology("New password field cannot be empty")
            newp = (request.form.get("newpc"))
            if newp == None:
                return apology("New password confirmation field cannot be empty")

            #If both new password and confirmation match, update users database
            if new == newp:
                hash = db.execute ("UPDATE users SET hash = :hash WHERE id = :id", hash = generate_password_hash(new), id = session["user_id"])
                flash("Password updated!")
                return redirect("/")
            else:
                return apology("New passsword must match with confirmation")
    else:
        return render_template("change.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
