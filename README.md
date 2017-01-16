# Item Catalog
----

## What is it?
Allows users to register and login using OAuth2 providers Google & Facebook so they can create lists of items in distict categories.  All categories and items are viewable but they can only be added to, edited, or deleted by the user who created them.

The web server is written in [Python](https://www.python.org/) using [Flask](http://flask.pocoo.org/) framework and the database uses [SQLite](https://sqlite.org/).


## Installation
1. Download and install [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
	* Checkout these [install instructions](https://www.virtualbox.org/manual/ch01.html#intro-installing)
2. Download and install [Vagrant](https://www.vagrantup.com/downloads.html). Be sure to grant network permissions.
	* Checkout these [install instructions](https://www.vagrantup.com/docs/installation/)
    * Optionally, see this [quickstart guide](https://www.vagrantup.com/docs/getting-started/)
3. If using Windows you will also need to install an app in order to ssh to the Vagrant virual machine.  I would recomment [Git](https://git-scm.com/download/win).
4. Visit the [Google API Console](https://console.developers.google.com/) and configure OAuth 2.0 credentials
	* Create a project for the Item Catalog
	* Select **Credentials** from the menu on the left.
	* Create an **OAuth Client ID** and configure the **consent screen**
	* Select **Web application** as the application type
	* Set the **Authorized JavaScript origins** as needed.  For local testing use, http://localhost:8000
	* Record your **Client ID** and **Client secret** in file `client_secrets.json`
	* Additional info can be found in [this guide](https://developers.google.com/identity/protocols/OAuth2)
4. Visit the [Facebook Developers page](https://developers.facebook.com/quickstarts/?platform=web) and configure OAuth 2.0 credentials
	* **Add a New App** and enter a **Display Name** and select a **Category**
	* On the left, select **Settings** from the menu
	* Set the **Site URL** as needed.  For local testing use, http://localhost:8000
	* Record your **App ID** and **App Secret** in file `fb_client_secrets.json`
	* Additional info can be found in [this guide](https://developers.facebook.com/docs/facebook-login)


## Development
Modify the site as needed. All HTML files are located in the `templates` directory. Styling can be changed using the CSS file `style.css` in the `/static/css` folder.

A blank `catalog.db` database can be created by running this command from a terminal in the project folder:
```sh
$ python database_setup.py
```

The application's server code can be modified in file `application.py`.


#### Running Locally
Ensure database, `catalog.db` exists in the application directory.  If not, run `database_setup`:
```sh
$ python database_setup.py
```

The application's Python server can be started from within the Vagrant virtual machine. To start the Vagrant VM, first run this command from a Terminal within the application's directory. 
```sh
$ vagrant up
```

Once the VM is up and running connect to it using this command:
```sh
$ vagrant ssh
```

This should result in the following prompt in the VM:
```sh
The shared directory is located at /vagrant
To access your shared files: cd /vagrant
Last login: Mon Jan 16 13:22:01 2017 from 10.0.0.1
vagrant@vagrant-ubuntu-trusty-32:~$ 
```

To start the Flask web server you will need to first navigate to the app's directory using this command:
```sh
vagrant@vagrant-ubuntu-trusty-32:~$ cd /vagrant/catalog
```

Then start `application`:
```sh
vagrant@vagrant-ubuntu-trusty-32:/vagrant/catalog$ python application.py
```

Which should result in the server starting and listening on port 8000. The server can be killed by pressing <kbd>CTRL</kbd>+<kbd>C</kbd>.
```sh
 * Running on http://0.0.0.0:8000/
 * Restarting with reloader
```

The site will then be avialible at http://localhost:8000/.
JSON representations of the database are availible at:

* http://localhost:8000/catalog.JSON/
* http://localhost:8000/category/1/JSON/ 
	* "1" is the Category ID
* http://localhost:8000/category/1/2/JSON/ 
	* "1" is the Category ID
	* "2" is the Item ID


If you wish to use a different port change it on line 688 of `application.py`.
```python
	app.run(host="0.0.0.0", port=8000)
```



## Todos
- [ ] Add images to items with CRUD functionality


## License
MIT
