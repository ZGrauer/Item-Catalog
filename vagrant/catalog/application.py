from flask import (Flask, render_template, request, redirect, make_response,
                   url_for, flash, jsonify, session as login_session)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from database_setup import Base, User, Category, Item
from oauth2client.client import (OAuth2Credentials, flow_from_clientsecrets,
                                 FlowExchangeError)
import httplib2
import requests
import json
import datetime
import random
import string

app = Flask(__name__)

# Bind the engine to local database.
# catalog.db can be created by running "database_setup.py"
engine = create_engine("sqlite:///catalog.db")
Base.metadata.bind = engine

# DBSession() instance (session) establishes all conversations
# with the database
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Category Routes
@app.route("/")
@app.route("/category")
def categories():
    '''Renders the HTML for the main page/index

    Args:

    Returns:
        rendered HTML
    '''
    categories = session.query(Category).all()
    new_items = session.query(Item).order_by(Item.create_date.desc()
                                             ).limit(10).all()
    if len(categories) == 0:
        flash("No Categories")
    return render_template("index.html", categories=categories,
                           new_items=new_items, login_session=login_session)


@app.route("/category/new/", methods=["GET", "POST"])
def newCategory():
    '''Renders the HTML when creating a new category. Also handles form POSTs

    Args:

    Returns:
        rendered HTML
    '''
    if "username" not in login_session:
        return redirect("/login")
    if request.method == "POST":
        newCategory = Category(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash("New category has been added.")
        return redirect(url_for("categories"))
    else:
        return render_template("newcategory.html", login_session=login_session)


@app.route("/category/<int:category_id>/edit/", methods=["GET", "POST"])
def editCategory(category_id):
    '''Renders the HTML when editing category. Also handles form POSTs

    Args:
        category_id: int from the URL. Represents Category.id
    Returns:
        rendered HTML
    '''
    if "username" not in login_session:
        return redirect("/login")

    try:
        category = session.query(Category).filter_by(id=category_id).one()
        author = getUserInfo(category.user_id)
    except NoResultFound:
        flash("Category not found")
        return redirect(url_for("categories"))

    if author.id != login_session['user_id']:
        flash("You're not the author of this category. Not authorized!")
        return redirect(url_for("items", category_id=category.id))
    if request.method == "POST":
        category.name = request.form['name']
        session.add(category)
        session.commit()
        flash("Category %s has been updated." % category.name)
        return redirect(url_for("categories"))
    else:
        return render_template("editcategory.html", category=category,
                               login_session=login_session)


@app.route("/category/<int:category_id>/delete/", methods=["GET", "POST"])
def deleteCategory(category_id):
    '''Renders the HTML when deleting category. Also handles form POSTs

    Args:
        category_id: int from the URL. Represents Category.id
    Returns:
        rendered HTML
    '''
    if "username" not in login_session:
        return redirect("/login")

    try:
        category = session.query(Category).filter_by(id=category_id).one()
        items = session.query(Item).filter_by(category_id=category.id).all()
        author = getUserInfo(category.user_id)
    except NoResultFound:
        flash("Category not found")
        return redirect(url_for("categories"))

    if author.id != login_session['user_id']:
        flash("You're not the author of this category. Not authorized!")
        return redirect(url_for("items", category_id=category.id))

    if request.method == "POST":
        for i in items:
            session.delete(i)
            session.commit()
        session.delete(category)
        session.commit()
        flash("Category %s and %s items have been deleted." %
              (category.name, str(len(items))))
        return redirect(url_for("categories"))
    else:
        return render_template("deletecategory.html", category=category,
                               login_session=login_session)


@app.route("/category/<int:category_id>/")
def items(category_id):
    '''Renders the HTML when viewing all items in a category

    Args:
        category_id: int from the URL. Represents Category.id
    Returns:
        rendered HTML
    '''
    categories = session.query(Category).all()
    try:
        category = session.query(Category).filter_by(id=category_id).one()
        items = session.query(Item).filter_by(category_id=category.id)
        author = getUserInfo(category.user_id)
    except NoResultFound:
        flash("Category not found")
        return redirect(url_for("categories"))

    if items.count() == 0:
        flash("No items in category %s." % category.name)
    return render_template("category.html", category=category,
                           categories=categories, items=items,
                           login_session=login_session,
                           author=author)


# View/Edit/Delete Item Routes
@app.route("/category/<int:category_id>/<int:item_id>/")
def viewItem(category_id, item_id):
    '''Renders the HTML when viewing a specific item

    Args:
        category_id: int from the URL. Represents Category.id
        item_id: int from the URL. Represents Item.id
    Returns:
        rendered HTML
    '''
    try:
        category = session.query(Category).filter_by(id=category_id).one()
        item = session.query(Item).filter_by(id=item_id,
                                             category=category).one()
        author = getUserInfo(item.user_id)
    except NoResultFound:
        flash("Item not found in category")
        return redirect(url_for("categories"))
    return render_template("viewitem.html", category=category, item=item,
                           login_session=login_session,
                           author=author)


@app.route("/category/<int:category_id>/new/", methods=["GET", "POST"])
def newItem(category_id):
    '''Renders the HTML when creating a new item in a category

    Args:
        category_id: int from the URL. Represents Category.id
    Returns:
        rendered HTML
    '''
    if "username" not in login_session:
        return redirect("/login")

    try:
        category = session.query(Category).filter_by(id=category_id).one()
        author = getUserInfo(category.user_id)
    except NoResultFound:
        flash("Category not found")
        return redirect(url_for("categories"))

    if author.id != login_session['user_id']:
        flash("You're not the author of this category. Not authorized!")
        return redirect(url_for("items", category_id=category.id))

    if request.method == "POST":
        newItem = Item(name=request.form['name'],
                       description=request.form['desc'],
                       category_id=category_id,
                       user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash("Item %s has been added." % newItem.name)
        return redirect(url_for("items", category_id=category_id))
    else:
        return render_template("newitem.html", category=category,
                               login_session=login_session)


@app.route("/category/<int:category_id>/<int:item_id>/edit/",
           methods=["GET", "POST"])
def editItem(category_id, item_id):
    '''Renders the HTML when editing an item. Also handles form POSTs

    Args:
        category_id: int from the URL. Represents Category.id
        item_id: int from the URL. Represents Item.id
    Returns:
        rendered HTML
    '''
    if "username" not in login_session:
        return redirect("/login")

    categories = session.query(Category).all()
    try:
        category = session.query(Category).filter_by(id=category_id).one()
        item = session.query(Item).filter_by(id=item_id,
                                             category=category).one()
        author = getUserInfo(item.user_id)
    except NoResultFound:
        flash("Item not found in category.")
        return redirect(url_for("categories"))

    if author.id != login_session['user_id']:
        flash("You're not the author of this item. Not authorized!")
        return redirect(url_for("viewItem", category_id=item.category_id,
                                item_id=item.id))

    if request.method == "POST":
        if request.form['name']:
            item.name = request.form['name']
            item.description = request.form['description']
            item.category_id = int(request.form['item_category'])
        session.add(item)
        session.commit()
        flash("Item %s has been updated." % item.name)
        return redirect(url_for("items", category_id=category_id))
    else:
        return render_template("edititem.html", category=category,
                               categories=categories, item=item,
                               login_session=login_session)


@app.route("/category/<int:category_id>/<int:item_id>/delete/",
           methods=["GET", "POST"])
def deleteItem(category_id, item_id):
    '''Renders the HTML when deleting an item. Also handles form POSTs

    Args:
        category_id: int from the URL. Represents Category.id
        item_id: int from the URL. Represents Item.id
    Returns:
        rendered HTML
    '''
    if "username" not in login_session:
        return redirect("/login")
    try:
        category = session.query(Category).filter_by(id=category_id).one()
        item = session.query(Item).filter_by(id=item_id,
                                             category=category).one()
        author = getUserInfo(item.user_id)
    except NoResultFound:
        flash("Item not found in category.")
        return redirect(url_for("categories"))

    if author.id != login_session['user_id']:
        flash("You're not the author of this item. Not authorized!")
        return redirect(url_for("viewItem", category_id=item.category_id,
                                item_id=item.id))

    if request.method == "POST":
        session.delete(item)
        session.commit()
        flash("Item %s has been deleted." % item.name)
        return redirect(url_for("items", category_id=category_id))
    else:
        return render_template("deleteitem.html", category=category, item=item,
                               login_session=login_session)


# JSON Routes
@app.route("/catalog.JSON/")
def catalogJASON():
    '''Generates and displays JSON for entire catalog of items in database

    Args:

    Returns:
        JSON
    '''
    categories = session.query(Category).all()
    CategoryItems = [c.serialize for c in categories]
    for c in CategoryItems:
        items = session.query(Item).filter_by(category_id=c['id']).all()
        items = [i.serialize for i in items]
        c['items'] = items
    return jsonify(Catalog=CategoryItems)


@app.route("/category/<int:category_id>/JSON/")
def categoryJASON(category_id):
    '''Generates and displays JSON for all items in 1 category

    Args:

    Returns:
        JSON
    '''
    try:
        category = session.query(Category).filter_by(id=category_id).one()
        items = session.query(Item).filter_by(category_id=category.id).all()
    except NoResultFound:
        flash("Category not found.")
        return redirect(url_for("categories"))
    return jsonify(CategoryItems=[i.serialize for i in items])


@app.route("/category/<int:category_id>/<int:item_id>/JSON/")
def itemJASON(category_id, item_id):
    '''Generates and displays JSON for 1 item

    Args:

    Returns:
        JSON
    '''
    try:
        category = session.query(Category).filter_by(id=category_id).one()
        item = session.query(Item).filter_by(id=item_id).one()
    except NoResultFound:
        flash("Category not found.")
        return redirect(url_for("categories"))
    return jsonify(CategoryItem=item.serialize)


@app.route("/login")
def showLogin():
    '''Creates an anti-forgery state token for OAuth process.
    Renders the HTML for the login page.

    Args:

    Returns:
        rendered HTML
    '''
    state = "".join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template("login.html", STATE=state)


# OAuth2 Routes
# Google, then Facebook
@app.route("/disconnect")
def disconnect():
    '''Disconnects the logged in user based on OAuth2 provider

    Args:

    Returns:
        flash message that will be displayed on the main index page
    '''
    # Check if the provider is listed in the session.
    # If the provider isn't listed, then not logged in.
    if 'provider' in login_session:
        # Call provider specific disconnect code
        logout_success = False
        if login_session['provider'] == "google":
            logout_success = gdisconnect()
            del login_session['gplus_id']
        if login_session['provider'] == "facebook":
            logout_success = fbdisconnect()
            del login_session['facebook_id']

        # Delete all common session data
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        del login_session['access_token']
        # Display flash based on Google or Facebook response
        if logout_success is True:
            flash("You have successfully been logged out.")
        else:
            flash("Failed to revoke your token.")
    else:
        flash("You were not logged in")

    return redirect(url_for("categories"))


@app.route("/gconnect", methods=['POST'])
def gconnect():
    '''Logs a user into the site using Google OAuth2 hybrid process

    Args:

    Returns:
        Response.  Indicates if the login was successful or not
    '''
    CLIENT_ID = json.loads(open("client_secrets.json",
                                "r").read())['web']['client_id']
    APPLICATION_NAME = "Item Catalog"

    # Validate state token from user against one from login route
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps("Invalid state parameter."), 401)
        response.headers['Content-Type'] = "application/json"
        return response

    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        # Create flow, add server secrets, exchange with google
        oauth_flow = flow_from_clientsecrets("client_secrets.json", scope="")
        oauth_flow.redirect_uri = "postmessage"
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps("Failed to upgrade the authorization code."), 401)
        response.headers['Content-Type'] = "application/json"
        return response

    # Check that the returned access token is valid.
    access_token = credentials.access_token
    url = ("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s"
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = "application/json"
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = "application/json"
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = "application/json"
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            "Current user is already connected."), 200)
        response.headers['Content-Type'] = "application/json"
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = "google"

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = "<h3>Welcome, " + login_session['username'] + "!</h3>"
    output += '<img src="'
    output += login_session['picture']
    output += ' " class = "login-pic"> '
    flash("You're logged in as %s" % login_session['username'])
    return output


@app.route("/gdisconnect")
def gdisconnect():
    '''Disconnects a user from site using Google OAuth2

    Args:

    Returns:
        Boolean.  True if successfully logged user out and revoked token
    '''
    # Get google access token
    access_token = login_session['access_token']
    if access_token is None:
    	response = make_response(json.dumps("Current user not connected."),
                                 401)
        response.headers['Content-Type'] = "application/json"
        return response
    # Revoke token
    url = "https://accounts.google.com/o/oauth2/revoke"
    url += "?token=%s" % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, "GET")[0]
    # If not successful return response
    if result['status'] != "200":
        return False
    else:
        return True


@app.route("/fbconnect", methods=['POST'])
def fbconnect():
    '''Logs a user into the site using Facebook OAuth2

    Args:

    Returns:
        Response.  Indicates if the login was successful or not
    '''
    # Validate state token from user against one from login route
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps("Invalid state parameter."), 401)
        response.headers['Content-Type'] = "application/json"
        return response

    # Get access token
    access_token = request.data

    # Get the locally stored client secret and app id for Facebook
    app_id = json.loads(open("fb_client_secrets.json", "r").read())[
        'web']['app_id']
    app_secret = json.loads(
        open("fb_client_secrets.json", "r").read())['web']['app_secret']
    url = "https://graph.facebook.com/oauth/access_token"
    url += "?grant_type=fb_exchange_token&client_id="
    url += "%s&client_secret=%s&fb_exchange_token=%s" % (app_id, app_secret,
                                                         access_token)
    h = httplib2.Http()
    result = h.request(url, "GET")[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    url = "https://graph.facebook.com/v2.4/me?"
    url += "%s&fields=name,id,email" % token
    h = httplib2.Http()
    result = h.request(url, "GET")[1]
    data = json.loads(result)
    login_session['provider'] = "facebook"
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to
    # properly logout.
    # Strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = "https://graph.facebook.com/v2.4/me/picture?"
    url += "%s&redirect=0&height=200&width=200" % token
    h = httplib2.Http()
    result = h.request(url, "GET")[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # See if user exists in our database
    # if not, add them
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = "<h3>Welcome, " + login_session['username'] + "!</h3>"
    output += '<img src="' + login_session['picture']
    output += ' " class = "login-pic"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    '''Disconnects a user from site using Facebook OAuth2

    Args:

    Returns:
        Boolean.  True if successfully logged user out and revoked token
    '''
    facebook_id = login_session['facebook_id']
    # Access token must be included to successfully logout
    access_token = login_session['access_token']
    url = "https://graph.facebook.com/"
    url += "%s/permissions?access_token=%s" % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return result == '{"success":true}'


# Helpers for user table and login
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


if __name__ == "__main__":
    app.secret_key = "Lw0J9l-lEp21ImwjLD6Y8I0z"
    app.debug = True
    app.run(host="0.0.0.0", port=8000)
