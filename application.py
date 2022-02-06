import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
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
    user_id = session["user_id"]
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    portfolio = db.execute("SELECT * FROM portfolio WHERE id = ?", user_id)
    final = cash
    for stock in portfolio:
        price = lookup(stock["symbol"])["price"]
        total = stock["shares"] * price
        stock.update({'price': price, 'total': total})
        name = lookup(stock["symbol"])["name"]
        final += total
    return render_template("index.html", stocks=portfolio, cash=cash, total=final, usd = usd)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    if request.method == "POST":
        shares = request.form.get("shares")
        symbol = request.form.get("symbol")
        quote = lookup(symbol)
        if not quote:
            return apology("enter valid symbol.", 403)
        if not shares:
            return apology("please increase the number of shares", 403)
        price = quote.get("price")
        name = quote.get("name")
        total = int(shares) * float(price)
        current_cash = db.execute("SELECT cash FROM users WHERE id = :uid", uid=session["user_id"])[0]["cash"]
        if current_cash < total:
            return apology("you do not have sufficient funds.", 403)
        db.execute("INSERT INTO transactions(id, name, shares, price, total, type) VALUES(:uid,:name,:shares,:price,:total,:ttype)",uid=session["user_id"] ,name=name,shares=shares,price=price,total=total,ttype="buy")
        transaction_value = current_cash - total
        db.execute("UPDATE users SET cash=:final WHERE id=:uid", final=transaction_value, uid=session["user_id"])
        current_portfolio = db.execute("SELECT shares FROM portfolio WHERE symbol=:symbol", symbol=symbol)
        if not current_portfolio:
            db.execute("INSERT INTO portfolio(id, shares, symbol) VALUES (?,?,?)", session["user_id"], shares, symbol)
        else:
            db.execute("UPDATE portfolio SET shares=shares+:shares WHERE symbol=:symbol",shares=shares, symbol=symbol);
    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT * FROM transactions WHERE id = :uid", uid = session["user_id"])
    return render_template("history.html", history=rows, usd=usd)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    symbol = request.form.get("symbol")
    quote = lookup(symbol)
    if not symbol:
        return apology("enter a symbol", 400)
    if not quote:
        return apology("enter valid symbol.", 400)
    else:
        company = quote.get("name")
        price = quote.get("price")
        return render_template("quoted.html", symbol=symbol.upper(), company=company, price=usd(price))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    name = request.form.get("name")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    if request.method == "POST":
        if not name:
            return apology("must provide username.", 403)
        if not password:
            return apology("must provide password.", 403)
        if not confirmation:
            return apology("must enter the password again.", 403)
        if password != confirmation:
            return apology("must enter the same password.", 403)
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=name)
        hash_password = generate_password_hash(password)
        if len(rows) == 0:
            db.execute("INSERT INTO users(username,hash) VALUES(?,?)", name, hash_password)
            return redirect("/")
        else:
            return apology("Select another username.", 403)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        return render_template("sell.html")
    symbol = request.form.get("symbol")
    shares = request.form.get("shares")
    quote = lookup(symbol)
    if request.method == "POST":
        if not symbol:
            return apology("please enter a symbol", 403)
        if not quote:
            return apology("please enter a valid symbol", 403)
        if not shares:
            return apology("please enter more shares", 403)
    price = quote.get("price")
    name = quote.get("name")
    total = int(shares) * float(price)
    current_cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    final = total + current_cash
    SHARES = db.execute("SELECT * FROM portfolio WHERE id = ? AND symbol = ?", session["user_id"],symbol)[0]["shares"]
    if not SHARES:
        return apology("you do not own these shares", 403)
    if SHARES < int(shares):
        return apology("you do not have enough shares", 403)
    else:
        final_shares = SHARES - int(shares)
    db.execute("INSERT INTO transactions(id, name, shares, price, type, total) VALUES(?,?,?,?,?,?)", session["user_id"], name, shares, price, "sell", total)
    db.execute("UPDATE portfolio SET shares=:fs", fs=final_shares)
    if final_shares == 0:
        db.execute("DELETE FROM portfolio WHERE shares=?", 0)
    db.execute("UPDATE users SET cash = :fc", fc=final)
    return redirect("/")

@app.route("/funds", methods=["GET", "POST"])
@login_required
def change_funds():
    """Increase the cash the user have"""
    if request.method == "GET":
        return render_template("funds.html")
    if request.method == "POST":
        amount = request.form.get("amount")
        cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = session["user_id"])[0]["cash"]
        total = cash + float(amount)
        db.execute("UPDATE users SET cash = :cash WHERE id = :id",
                    cash = total,
                    id = session["user_id"])
    return redirect("/")

@app.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    """Increase the cash the user have"""
    if request.method == "GET":
        return render_template("password.html")
    if request.method == "POST":
        new_password = request.form.get("password")
        if not new_password:
            return apology("Enter a new password", 403)
        hash_password = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])
        new_hash_password = generate_password_hash(new_password)
        if hash_password == new_hash_password:
            return apology("entered password is the same as the old one", 403)
        db.execute("UPDATE users SET hash = :new WHERE id = :uid", new = new_hash_password, uid = session["user_id"])
    return redirect("/")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
