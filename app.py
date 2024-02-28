import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application=l,
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

## ------awal index
@app.route("/")
def index():
    session.clear()

    # Redirect user to login form
    return render_template("index.html")

## --------end of index
@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/latihan")
def latihan():
    return render_template("latihan.html")

@app.route('/level1')
def level1():
    return render_template('level1.html')

@app.route('/level2')
def level2():
    return render_template('level2.html')

@app.route('/level3')
def level3():
    return render_template('level3.html')

@app.route('/fiksi')
def fiksi():
    return render_template('fiksi.html')

@app.route('/sastra')
def sastra():
    return render_template('sastra.html')

@app.route('/informasi')
def informasi():
    return render_template('informasi.html')

@app.route("/tryout")
@login_required
def tryout():
    return render_template("tryout.html")

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares_str = request.form.get("shares")
        try:
            shares = int(shares_str)
            if shares <= 0:
                return apology("must provide positive integer")
        except ValueError: #this part also took verylong time to figure out how to prevent non numeric input
            return apology("shares must be a positive integer")
        if not symbol:
            return apology("must provide symbol")

        quote = lookup(symbol)
        if quote is None:
            return apology("symbol not found")

        price = float(quote["price"])
        total_cost = shares * price
        cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])[0]["cash"]

        if cash < total_cost:
            return apology("not enough cash")

        # update users table db
        db.execute("UPDATE users SET cash = cash - :total_cost WHERE id = :user_id",
                   total_cost=total_cost, user_id=session["user_id"])

        # add purchase to history
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
                   user_id=session["user_id"], symbol=symbol, shares=shares, price=price)

        flash(f"Bought {shares} shares of {symbol} for {usd(total_cost)}!")
        return redirect("/")

    else:
        return render_template("buy.html")

## ---------batas buy---------##


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # query db of users transactions
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = :user_id ORDER BY timestamp DESC",
                              user_id=session["user_id"])

    # render history page with transactions
    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
    """Get stock quote."""  # nomor 2
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = lookup(symbol)
        if not quote:
            return apology("invalid symbol", 400)
        return render_template("quote.html", quote=quote)
    else:
        return render_template("quote.html")
# -------end of quote--------#


@app.route("/register", methods=["GET", "POST"])  # INI YANG PERTAMA DIKERJAKAN
def register():
    """Register user FIRST"""
    session.clear()  # forget any user user id

    if request.method == "POST":

        # Ensue username was sumitted
        if not request.form.get("username"):
            return apology("enter user name", 400)

        # ensure passowrd is submitted
        elif not request.form.get("password"):
            return apology("enter password", 400)

        # ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # ensure password and confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # query db for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # ensure username doesn't already exist
        if len(rows) != 0:
            return apology("username already exists", 400)
        # Separate the values for better inspection
        username = request.form.get("username")
        hashed_password = generate_password_hash(request.form.get("password"))
        #print("Username:", username)
        #print("Hashed Password:", hashed_password)

        # Execute the insertion command
        #db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", (username, hashed_password))

        #so struggling with this line lots of trial and errorrrrrr
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", request.form.get("username"), generate_password_hash(request.form.get("password")))
        #db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", (request.form.get("username"), generate_password_hash(request.form.get("password"))))
        #db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", (request.form.get("username"), generate_password_hash(request.form.get("password")),))
        #db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", request.form.get("username"), generate_password_hash(request.form.get("password")))

        # query db for the newly added username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # redirect user to homepage
        return redirect("/")
    # user reached route via GET
    else:
        return render_template("register.html")

## ========= end of registrasi ===========##


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock 5th"""
    # get user's stocks
    stocks = db.execute(
        "SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING total_shares > 0", user_id=session["user_id"])

    # when user submit a form
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = float ( request.form.get("shares"))
        if not symbol:
            return apology("must provide symbol")
        elif not shares or shares <= 0:
            return apology("must provide positive number of shares")
        else:
            shares = float(shares)

        for stock in stocks:
            if stock["symbol"] == symbol:
                if stock["total_shares"] < shares:
                    return apology("not enough shares")
                else:
                    # get quote
                    quote = lookup(symbol)
                    if quote is None:
                        return apology("symbol not found")
                    price = float ( quote["price"] )
                    total_sale = shares * price
                    total_sale = float ( total_sale )
                    price = float ( price )

                    # update users table
                    db.execute("UPDATE users SET cash = cash + :total_sale WHERE id = :user_id",
                               total_sale=total_sale, user_id=session["user_id"])

                    # update history of transaction
                    db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES(:user_id, :symbol, :shares, :price)",
                               user_id=session["user_id"], symbol=symbol, shares=-shares, price=price)

                    flash(f"Sold {shares} shares of {symbol} for {usd(total_sale)}!")
                    return redirect("/")

        return apology("symbol not found")
    # If the user visit the page
    else:
        return render_template("sell.html", stocks=stocks)
