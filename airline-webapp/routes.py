# Importing the Flask Framework

from datetime import timedelta
import bcrypt
from flask import *
import database
import configparser
from markupsafe import escape
from flask import Flask, session, redirect, url_for, request, flash
from flask_session import Session
from datetime import datetime

# appsetup
app = Flask(__name__)
app.secret_key = 'SoMeSeCrEtKeYhErE'

# Configure session settings
app.config['SESSION_COOKIE_SECURE'] = False   # Set to False since we're using HTTP
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents JavaScript from accessing session cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
app.config['SESSION_TYPE'] = 'filesystem'  # Store session data server-side
app.config['SESSION_PERMANENT'] = False  # Sessions will not be permanent
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)  # Session expires after 1 minute of inactivity

Session(app)
page = {}
# Debug = true if you want debug output on error ; change to false if you dont
app.debug = True


# Read my unikey to show me a personalised app
config = configparser.ConfigParser()
config.read('config.ini')
dbuser = config['DATABASE']['user']
portchoice = config['FLASK']['port']
if portchoice == '10000':
    print('ERROR: Please change config.ini as in the comments or Lab instructions')
    exit(0)

@app.before_request
def ensure_isadmin():
    if 'isadmin' not in session:
        session['isadmin'] = False  # Default value if not set


###########################################################################################
###########################################################################################
####                                 Database operative routes                         ####
###########################################################################################
###########################################################################################

# Helper functions 

# Tia
def password_hash(password):
    """
    bcrypt hashing & salting.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


#####################################################
##  INDEX
#####################################################

# What happens when we go to our website (home page)
@app.route('/')
def index():
    # If the user is not logged in, then make them go to the login page
    if( 'logged_in' not in session or not session['logged_in']):
        return redirect(url_for('login'))
    page['username'] = dbuser
    page['title'] = 'Welcome'
    return render_template('welcome.html', session=session, page=page)

#####################################################
# User Login related                        
#####################################################
# login
@app.route('/login', methods=['POST', 'GET'])
def login():
    page = {'title' : 'Login', 'dbuser' : dbuser}
    # If it's a post method handle it nicely
    if(request.method == 'POST'):
        # Get our login value
        val = database.check_login(request.form['userid'], request.form['password'])
        print(val)
        print(request.form)
        # If our database connection gave back an error
        if(val == None):
            errortext = "Error with the database connection."
            errortext += "Please check your terminal and make sure you updated your INI files."
            flash(errortext)
            return redirect(url_for('login'))

        # If it's null, or nothing came up, flash a message saying error
        # And make them go back to the login screen
        if(val is None or len(val) < 1):
            flash('There was an error logging you in')
            return redirect(url_for('login'))

        # If it was successful, then we can log them in :)
        print(val)
        session['name'] = val['firstname']
        session['userid'] = request.form['userid']
        session['logged_in'] = True
        session['isadmin'] = val['isadmin']
        return redirect(url_for('index'))
    else:
        # Else, they're just looking at the page :)
        if('logged_in' in session and session['logged_in'] == True):
            return redirect(url_for('index'))
        return render_template('index.html', page=page)

# logout
@app.route('/logout')
def logout():
    session['logged_in'] = False
    session.clear()  # Clears all session data
    flash('You have been logged out')
    return redirect(url_for('index'))

########################
#List All Items#
########################

@app.route('/users')
def list_users():
    '''
    List all rows in users by calling the relvant database calls and pushing to the appropriate template
    '''
    # connect to the database and call the relevant function
    users_listdict = database.list_users()

    # Handle the null condition
    if (users_listdict is None):
        # Create an empty list and show error message
        users_listdict = []
        flash('Error, there are no rows in users')
    page['title'] = 'List Contents of users'
    return render_template('list_users.html', page=page, session=session, users=users_listdict)
    

########################
#List Single Items#
########################


@app.route('/users/<userid>')
def list_single_users(userid):
    '''
    List all rows in users that match a particular id attribute userid by calling the 
    relevant database calls and pushing to the appropriate template
    '''

    # connect to the database and call the relevant function
    users_listdict = None
    users_listdict = database.list_users_equifilter("userid", userid)

    # Handle the null condition
    if (users_listdict is None or len(users_listdict) == 0):
        # Create an empty list and show error message
        users_listdict = []
        flash('Error, there are no rows in users that match the attribute "userid" for the value '+userid)
    page['title'] = 'List Single userid for users'
    return render_template('list_users.html', page=page, session=session, users=users_listdict)


########################
#List Search Items#
########################

@app.route('/consolidated/users')
def list_consolidated_users():
    '''
    List all rows in users join userroles 
    by calling the relvant database calls and pushing to the appropriate template
    '''
    # connect to the database and call the relevant function
    users_userroles_listdict = database.list_consolidated_users()

    # Handle the null condition
    if (users_userroles_listdict is None):
        # Create an empty list and show error message
        users_userroles_listdict = []
        flash('Error, there are no rows in users_userroles_listdict')
    page['title'] = 'List Contents of Users join Userroles'
    return render_template('list_consolidated_users.html', page=page, session=session, users=users_userroles_listdict)

@app.route('/user_stats')
def list_user_stats():
    '''
    List some user stats
    '''
    # connect to the database and call the relevant function
    user_stats = database.list_user_stats()

    # Handle the null condition
    if (user_stats is None):
        # Create an empty list and show error message
        user_stats = []
        flash('Error, there are no rows in user_stats')
    page['title'] = 'User Stats'
    return render_template('list_user_stats.html', page=page, session=session, users=user_stats)

@app.route('/users/search', methods=['POST', 'GET'])
def search_users_byname():
    '''
    List all rows in users that match a particular name
    by calling the relevant database calls and pushing to the appropriate template
    '''
    if(request.method == 'POST'):

        search = database.search_users_customfilter(request.form['searchfield'],"~",request.form['searchterm'])
        print(search)
        
        users_listdict = None

        if search == None:
            errortext = "Error with the database connection."
            errortext += "Please check your terminal and make sure you updated your INI files."
            flash(errortext)
            return redirect(url_for('index'))
        if search == None or len(search) < 1:
            flash(f"No items found for search: {request.form['searchfield']}, {request.form['searchterm']}")
            return redirect(url_for('index'))
        else:
            
            users_listdict = search
            # Handle the null condition'
            print(users_listdict)
            if (users_listdict is None or len(users_listdict) == 0):
                # Create an empty list and show error message
                users_listdict = []
                flash('Error, there are no rows in users that match the searchterm '+request.form['searchterm'])
            page['title'] = 'Users search by name'
            return render_template('list_users.html', page=page, session=session, users=users_listdict)
            

    else:
        return render_template('search_users.html', page=page, session=session)
        
@app.route('/users/delete/<userid>')
def delete_user(userid):
    '''
    Delete a user
    '''
    # connect to the database and call the relevant function
    resultval = database.delete_user(userid)
    
    page['title'] = f'List users after user {userid} has been deleted'
    return redirect(url_for('list_consolidated_users'))
    
@app.route('/users/update', methods=['POST','GET'])
def update_user():
    """
    Update details for a user
    """
    # # Check if the user is logged in, if not: back to login.
    if('logged_in' not in session or not session['logged_in']):
        return redirect(url_for('login'))
    
    # Need a check for isAdmin

    # Check if the user is an admin, if not, redirect to the homepage or an appropriate page
    if not session.get('isadmin', False):  # Default isadmin to False if not set
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))


    page['title'] = 'Update user details'

    userslist = None

    print("request form is:")
    newdict = {}
    print(request.form)

    validupdate = False
    # Check your incoming parameters
    if(request.method == 'POST'):

        # verify that at least one value is available:
        if ('userid' not in request.form):
            # should be an exit condition
            flash("Can not update without a userid")
            return redirect(url_for('list_users'))
        else:
            newdict['userid'] = request.form['userid']
            print("We have a value: ",newdict['userid'])

        if ('firstname' not in request.form):
            newdict['firstname'] = None
        else:
            validupdate = True
            newdict['firstname'] = request.form['firstname']
            print("We have a value: ",newdict['firstname'])

        if ('lastname' not in request.form):
            newdict['lastname'] = None
        else:
            validupdate = True
            newdict['lastname'] = request.form['lastname']
            print("We have a value: ",newdict['lastname'])

        if ('userroleid' not in request.form):
            newdict['userroleid'] = None
        else:
            validupdate = True
            newdict['userroleid'] = request.form['userroleid']
            print("We have a value: ",newdict['userroleid'])

        if ('password' not in request.form):
            newdict['password'] = None
        else:
            validupdate = True
            newdict['password'] = request.form['password']
            print("We have a value: ",newdict['password'])

        print('Update dict is:')
        print(newdict, validupdate)

        if validupdate:
            #forward to the database to manage update
            userslist = database.update_single_user(newdict['userid'],newdict['firstname'],newdict['lastname'],newdict['userroleid'],newdict['password'])
        else:
            # no updates
            flash("No updated values for user with userid")
            return redirect(url_for('list_users'))
        # Should redirect to your newly updated user
        return list_single_users(newdict['userid'])
    else:
        return redirect(url_for('list_consolidated_users'))

######
## Edit user
######
@app.route('/users/edit/<userid>', methods=['POST','GET'])
def edit_user(userid):
    """
    Edit a user
    """
    # # Check if the user is logged in, if not: back to login.
    if('logged_in' not in session or not session['logged_in']):
        return redirect(url_for('login'))
    
    # Need a check for isAdmin

    page['title'] = 'Edit user details'

    users_listdict = None
    users_listdict = database.list_users_equifilter("userid", userid)

    # Handle the null condition
    if (users_listdict is None or len(users_listdict) == 0):
        # Create an empty list and show error message
        users_listdict = []
        flash('Error, there are no rows in users that match the attribute "userid" for the value '+userid)

    userslist = None
    print("request form is:")
    newdict = {}
    print(request.form)
    user = users_listdict[0]
    validupdate = False

    # Check your incoming parameters
    if(request.method == 'POST'):

        # verify that at least one value is available:
        if ('userid' not in request.form):
            # should be an exit condition
            flash("Can not update without a userid")
            return redirect(url_for('list_users'))
        else:
            newdict['userid'] = request.form['userid']
            print("We have a value: ",newdict['userid'])

        if ('firstname' not in request.form):
            newdict['firstname'] = None
        else:
            validupdate = True
            newdict['firstname'] = request.form['firstname']
            print("We have a value: ",newdict['firstname'])

        if ('lastname' not in request.form):
            newdict['lastname'] = None
        else:
            validupdate = True
            newdict['lastname'] = request.form['lastname']
            print("We have a value: ",newdict['lastname'])

        if ('userroleid' not in request.form):
            newdict['userroleid'] = None
        else:
            validupdate = True
            newdict['userroleid'] = request.form['userroleid']
            print("We have a value: ",newdict['userroleid'])

        if 'password' in request.form and request.form['password']:
            # Hash the password before storing it
            validupdate = True
            hashed_password = password_hash(request.form['password'])
            newdict['password'] = hashed_password
            print("Hashed password is: ", newdict['password'])

        else:
            # ('password' not in request.form)
            newdict['password'] = None

        print('Update dict is:')
        print(newdict, validupdate)

        if validupdate:
            #forward to the database to manage update
            userslist = database.update_single_user(newdict['userid'],newdict['firstname'],newdict['lastname'],newdict['userroleid'],newdict['password'])
        else:
            # no updates
            flash("No updated values for user with userid")
            return redirect(url_for('list_users'))
        # Should redirect to your newly updated user
        return list_single_users(newdict['userid'])
    else:
        # assuming GET request, need to setup for this
        return render_template('edit_user.html',
                           session=session,
                           page=page,
                           userroles=database.list_userroles(),
                           user=user)


######
## add items
######
@app.route('/users/add', methods=['POST','GET'])
def add_user():
    """
    Add a new User
    """
    # # Check if the user is logged in, if not: back to login.
    if('logged_in' not in session or not session['logged_in']):
        return redirect(url_for('login'))
    
    # Need a check for isAdmin

    page['title'] = 'Add user details'

    userslist = None
    print("request form is:")
    newdict = {}
    print(request.form)

    # Check your incoming parameters
    if(request.method == 'POST'):

        # verify that all values are available:
        if ('userid' not in request.form):
            # should be an exit condition
            flash("Can not add user without a userid")
            return redirect(url_for('add_user'))
        else:
            newdict['userid'] = request.form['userid']
            print("We have a value: ",newdict['userid'])

        if ('firstname' not in request.form):
            newdict['firstname'] = 'Empty firstname'
        else:
            newdict['firstname'] = request.form['firstname']
            print("We have a value: ",newdict['firstname'])

        if ('lastname' not in request.form):
            newdict['lastname'] = 'Empty lastname'
        else:
            newdict['lastname'] = request.form['lastname']
            print("We have a value: ",newdict['lastname'])

        if ('userroleid' not in request.form):
            newdict['userroleid'] = 1 # default is traveler
        else:
            newdict['userroleid'] = request.form['userroleid']
            print("We have a value: ",newdict['userroleid'])

        if 'password' not in request.form or not request.form['password']:
            flash("Cannot add user without a password")
            return redirect(url_for('add_user'))
        else:
            # Hash the password before storing it
            hashed_password = password_hash(request.form['password'])
            newdict['password'] = hashed_password
            print("Hashed password is: ", newdict['password'])

        print('Insert parametesrs are:')
        print(newdict)

        database.add_user_insert(newdict['userid'], newdict['firstname'],newdict['lastname'],newdict['userroleid'],newdict['password'])
        # Should redirect to your newly updated user
        print("did it go wrong here?")
        return redirect(url_for('list_consolidated_users'))
    else:
        # assuming GET request, need to setup for this
        return render_template('add_user.html',
                           session=session,
                           page=page,
                           userroles=database.list_userroles())


@app.route('/admin/hash_passwords')
def hash_passwords():
    # Call the function to hash and salt existing passwords
    database.hash_existing_passwords()
    return "Hashed and salted all existing passwords!"

# Passengers table
# List all passengers -  40 rows per page
@app.route('/list_passengers', defaults={'page': 1})
@app.route('/list_passengers/page/<int:page>')
def list_passengers(page):
    # Check if the user is logged in, if not, redirect to login page
    if 'logged_in' not in session or not session['logged_in']:
        flash('You need to log in first.')
        return redirect(url_for('login'))

    per_page = 40  # Number of passengers per page
    offset = (page - 1) * per_page  # Calculate the offset

    # Query the database with a limit and offset
    passenger_listdict = database.show_all_passengers(per_page, offset)

    if not passenger_listdict:
        flash('No passengers found.')
        passenger_listdict = []

    # Assuming there's a function to get total passengers
    total_passengers = database.get_total_passenger_count()
    total_pages = (total_passengers // per_page) + (1 if total_passengers % per_page else 0)

    # Adjust the range of page numbers to display
    visible_pages = 10
    start_page = max(1, page - (visible_pages // 2))
    end_page = min(total_pages, page + (visible_pages // 2))
     # Get the ID of the newly added passenger from the request args
    new_passenger_id = request.args.get('new_passenger_id')

    # If we are near the start or end, adjust the range to show exactly 'visible_pages' number of pages
    if end_page - start_page < visible_pages - 1:
        if start_page == 1:
            end_page = min(visible_pages, total_pages)
        elif end_page == total_pages:
            start_page = max(1, total_pages - visible_pages + 1)

    return render_template(
        'list_passengers.html', 
        passengers=passenger_listdict, 
        page=page,
        session=session,
        total_pages=total_pages,
        start_page=start_page,
        end_page=end_page,
        new_passenger_id=new_passenger_id
    )

# Passengers table
# Display passengers' nationalities and count
@app.route('/passenger_nationality_summary')
def passenger_nationality_summary():
    # Check if the user is logged in, if not, redirect to login page
    if 'logged_in' not in session or not session['logged_in']:
        flash('You need to log in first.')
        return redirect(url_for('login'))

    # Fetch the nationality summary from the database
    nationality_summary = database.get_passenger_nationality_summary()

    if nationality_summary is None or len(nationality_summary) == 0:
        flash('No nationality data found.')
        nationality_summary = []
    
    page = {'title': 'Passenger Nationality Summary'}

    return render_template('nationality_summary.html', summary=nationality_summary, page=page, session=session)

#Passengers -  search passenger with PassengerID
@app.route('/search_passenger', methods=['POST'])
def search_passenger():
    # Check if the user is logged in, if not, redirect to login page
    if 'logged_in' not in session or not session['logged_in']:
        flash('You need to log in first.')
        return redirect(url_for('login'))

    passenger_id = escape(request.form.get('passenger_id'))  # Get the PassengerID from the form
    if passenger_id:
        passenger = database.get_passenger_by_id(passenger_id)  # Query to get passenger details
        
        if passenger:
            # If passenger is found, render the list_passengers.html with only that passenger
            page = {'title': 'Passenger Details'}
            return render_template('show_passenger.html', passenger=passenger, page=page, session=session)
        else:
            # If no passenger is found, flash a message and redirect to the list page
            flash('No passenger found with that PassengerID.')
            return redirect(url_for('list_passengers'))
    else:
        # In case no passenger_id is provided, just redirect back with an error
        flash('Please enter a valid Passenger ID.')
        return redirect(url_for('list_passengers'))

#Passengers - search passenger with selected fields
@app.route('/search_passenger_advanced', methods=['GET', 'POST'])
def search_passenger_advanced():
    # Check if the user is logged in, if not, redirect to login page
    if 'logged_in' not in session or not session['logged_in']:
        flash('You need to log in first.')
        return redirect(url_for('login'))

    page = {'title': 'Passenger Details'}
    current_page = 1 

    if request.method == 'POST':
        search_field = escape(request.form.get('search_field'))  # Escape the field to search by
        search_value = escape(request.form.get('search_value'))  # Escape the value to search for
        passengers = database.search_passenger_by_field(search_field, search_value)

        if passengers:
            return render_template('display_passengers_search_advance.html', passengers=passengers, current_page=current_page, page=page, session=session)
        else:
            flash('No passengers found.')
            return redirect(url_for('search_passenger_advanced'))

    return render_template('search_passenger.html', page=page, session=session)


# add passenger
@app.route('/add_passenger', methods=['GET', 'POST'])
def add_passenger():
        # Check if the user is logged in, if not, redirect to login page
    if 'logged_in' not in session or not session['logged_in']:
        flash('You need to log in first.')
        return redirect(url_for('login'))

    # Check if the user is an admin, if not, redirect to the homepage or an appropriate page
    if not session.get('isadmin', False):  # Default isadmin to False if not set
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    if request.method == 'POST':
        try:
            # Validating form data
            try:
                passenger_id = int(request.form['passenger_id'])  # Ensure it's an integer
            except ValueError:
                flash("Passenger ID must be an integer")
                raise ValueError("Passenger ID must be an integer")
            # Escape user inputs to prevent XSS attacks
            first_name = escape(request.form['first_name'].strip())
            last_name = escape(request.form['last_name'].strip())
            dob = escape(request.form['dob'])
            gender = escape(request.form['gender'].strip().upper())
            nationality = escape(request.form['nationality'].strip())
            passport_number = escape(request.form['passport_number'].strip())
            

            if not first_name:
                raise ValueError("First name cannot be empty")
            if not last_name:
                raise ValueError("Last name cannot be empty")
            
            # Additional validations (e.g., date, gender values)
            if gender not in ['M', 'F']:
                raise ValueError("Invalid gender value")
            
            # Validate date of birth
            try:
                datetime.strptime(dob, '%Y-%m-%d')  # Ensure correct date format
            except ValueError:
                raise ValueError("Invalid date format. Use YYYY-MM-DD")
            
            # Insert into the database after validation
            success = database.add_passenger_insert(passenger_id, request.form['first_name'], request.form['last_name'], dob, gender, nationality, passport_number)

            if success:
                # Retrieve the added passenger details from the database
                passenger = database.get_passenger_by_id(passenger_id)
                
                if passenger:
                    flash("Passenger added successfully!")
                    # Redirect or render the template with passenger details
                    return render_template('show_passenger.html', passenger=passenger, page={'title': 'Passenger Details'}, session=session)
                else:
                    flash("Error retrieving added passenger details.")
                    return redirect(url_for('list_passengers'))
            else:
                flash("Error adding passenger to the database.")
                return render_template('add_passenger.html', page={'title': 'Add New Passenger'}, session=session)

        except ValueError as e:
            # If validation fails, flash an error message and re-render the form
            flash("Error adding passenger")  # Display the specific validation error to the user
            return render_template('add_passenger.html', page={'title': 'Add New Passenger'}, session=session)

    # If GET, render the form
    return render_template('add_passenger.html', page={'title': 'Add New Passenger'}, session=session)

# delete passenger
@app.route('/delete_passenger/<int:passenger_id>', methods=['POST'])
def delete_passenger(passenger_id):
        # Check if the user is logged in, if not, redirect to login page
    if 'logged_in' not in session or not session['logged_in']:
        flash('You need to log in first.')
        return redirect(url_for('login'))

    # Check if the user is an admin, if not, redirect to the homepage or an appropriate page
    if not session.get('isadmin', False):  # Default isadmin to False if not set
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    
    if 'logged_in' in session and session['isadmin']:
        if database.is_passenger_associated_with_tickets(passenger_id):
            flash(f"Cannot delete passenger ID {passenger_id} because they are associated with tickets.", 'danger')
            return redirect(url_for('list_passengers'))
        database.delete_passenger(passenger_id)
        flash('Passenger deleted successfully.')
    else:
        flash('You do not have permission to delete passengers.')
    return redirect(url_for('list_passengers'))

# update passenger
@app.route('/update_passenger/<int:passenger_id>', methods=['GET', 'POST'])
def update_passenger(passenger_id):
    # Check if the user is logged in and is an admin
    if 'logged_in' not in session or not session['logged_in']:
        flash('You need to log in first.')
        return redirect(url_for('login'))
    if not session.get('isadmin', False):
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    # Handle POST request for updating passenger details
    if request.method == 'POST':
        try:
            # Escape user input to prevent XSS attacks
            new_passenger_id = int(escape(request.form.get('new_passenger_id')).strip())
            first_name = escape(request.form.get('first_name')).strip()
            last_name = escape(request.form.get('last_name')).strip()
            dob = escape(request.form.get('dob')).strip()
            gender = escape(request.form.get('gender')).strip().upper()
            nationality = escape(request.form.get('nationality')).strip()
            passport_number = escape(request.form.get('passport_number')).strip()

            # Validate that none of the fields are empty
            if not first_name or not last_name or not dob or not gender or not nationality or not passport_number:
                raise ValueError("All fields must be filled out.")

            # Validate date format
            from datetime import datetime
            try:
                datetime.strptime(dob, '%Y-%m-%d')  # Ensure correct date format
            except ValueError:
                raise ValueError("Invalid date format. Use YYYY-MM-DD")

            # Validate gender
            if gender not in ['M', 'F']:
                raise ValueError("Invalid gender value")
            
             # Check if passenger_id is being updated and if it is associated with tickets
            if new_passenger_id != passenger_id:
                if database.is_passenger_associated_with_tickets(passenger_id):
                    flash("Cannot update Passenger ID because it is associated with tickets.")
                    return redirect(url_for('update_passenger', passenger_id=passenger_id))


            # Update the passenger details in the database
            success = database.update_passenger(passenger_id, new_passenger_id, first_name, last_name, dob, gender, nationality, passport_number)

            if success:
                flash("Passenger details updated successfully!")
                return redirect(url_for('list_passengers'))
            else:
                flash("Error updating passenger details.")
        except ValueError as e:
            flash(str(e))
        # Handle GET request to prepopulate the form
    passenger = database.get_passenger_by_id(passenger_id)
    if passenger:
        # Assuming `passenger` is returned as a tuple or list, map it to a dictionary:
        passenger_dict = {
            'passengerid': passenger[0],
            'firstname': passenger[1],
            'lastname': passenger[2],
            'dateofbirth': passenger[3],
            'gender': passenger[4],
            'nationality': passenger[5],
            'passportnumber': passenger[6]
        }
        return render_template('update_passenger.html', passenger=passenger_dict, page={'title': 'Update Passenger'}, session=session)
    else:
        flash('Passenger not found.')
        return redirect(url_for('list_passengers'))

# Extension slim0093
@app.route('/passenger_ticket_summary', defaults={'page': 1})
@app.route('/passenger_ticket_summary/page/<int:page>')
def passenger_ticket_summary(page):
    """
    Route to display the passenger ticket summary with pagination
    """
    per_page = 40  # Number of rows per page
    offset = (page - 1) * per_page  # Calculate the offset for pagination

    # Fetch the paginated passenger ticket summary data from the database
    passenger_data = database.get_passenger_ticket_summary_paginated(per_page, offset)

    if not passenger_data:
        flash("No passengers found.")
        passenger_data = []

    # Get total passengers for pagination calculation
    total_passengers = database.get_total_passenger_count()
    total_pages = (total_passengers // per_page) + (1 if total_passengers % per_page else 0)

    # Adjust the range of page numbers to display
    visible_pages = 10
    start_page = max(1, page - (visible_pages // 2))
    end_page = min(total_pages, page + (visible_pages // 2))

    # Adjust page range if we're near the start or end
    if end_page - start_page < visible_pages - 1:
        if start_page == 1:
            end_page = min(visible_pages, total_pages)
        elif end_page == total_pages:
            start_page = max(1, total_pages - visible_pages + 1)
    

    return render_template(
        'passenger_ticket_summary.html', 
        passengers=passenger_data, 
        page=page,
        session=session,
        total_pages=total_pages,
        start_page=start_page,
        end_page=end_page,
    )

# Extension
@app.route('/search_passenger_by_id', methods=['GET', 'POST'])
def search_passenger_by_id_route():
    """
    Route to handle search by PassengerID.
    Displays a form to input PassengerID and shows the result in a table if found.
    """
    if request.method == 'POST':
        try:
            # Get the PassengerID from the form
            passenger_id = int(escape(request.form.get('passenger_id')))  # Escape user input

            # Call the function to search by PassengerID
            passenger = database.search_passenger_by_id(passenger_id)
            page['title'] = 'Passenger with tickets'
            if passenger:
                # If passenger is found, render the result
                return render_template('show_passenger_by_id.html', page=page, passenger=passenger, session=session)
            else:
                flash(f"No ticket found with PassengerID: {passenger_id}")
                return redirect(url_for('search_passenger_by_id_route'))

        except ValueError:
            flash("Please enter a valid Passenger ID.")
            return redirect(url_for('search_passenger_by_id_route'))
    else:
        return redirect(url_for('index'))
