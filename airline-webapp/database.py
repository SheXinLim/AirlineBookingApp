#!/usr/bin/env python3
# Imports
import pg8000
import configparser
import sys
import bcrypt
import traceback

#  Common Functions
##     database_connect()
##     dictfetchall(cursor,sqltext,params)
##     dictfetchone(cursor,sqltext,params)
##     print_sql_string(inputstring, params) 

# Functions for Security

# Salt - slim0093
def generate_salt():
    """
    Generates a random salt using bcrypt.
    """
    return bcrypt.gensalt()

# Hash - slim0093
def hash_password(password, salt):
    """
    Hashes a password using bcrypt and the provided salt.
    """
    # Hash the password using the provided salt
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def hash_existing_passwords():
    """
    Hashes and salts all existing plaintext passwords in the database.
    """
    # Get a connection to the database
    conn = database_connect()
    if conn is None:
        print("Unable to connect to the database.")
        return

    cur = conn.cursor()

    try:
        # Retrieve all users with their plaintext passwords
        sql = "SELECT userid, password FROM Users"
        cur.execute(sql)
        users = cur.fetchall()

        # Loop through each user and hash their password
        for user in users:
            userid = user[0]
            plaintext_password = user[1]

            # Generate salt
            salt = generate_salt()

            # Hash the password using the salt
            hashed_password = hash_password(plaintext_password, salt)

            # Update the database with the hashed password
            update_sql = """
                UPDATE Users
                SET password = %s
                WHERE userid = %s
            """
            cur.execute(update_sql, (hashed_password.decode('utf-8'), userid))

        # Commit the changes to the database
        conn.commit()
        print("All passwords have been hashed and salted successfully.")

    except Exception as e:
        print("An error occurred while hashing passwords:", e)
        conn.rollback()

    finally:
        cur.close()
        conn.close()

# sanitisation - slim00093
def check_for_sql_injection(input_string):
    """
    Checks for dangerous SQL keywords and special characters in the input.
    Returns True if the input contains risky content, False otherwise.
    """
    # Convert the input string to lowercase once for consistency
    lowered_input = input_string.lower()

    # List of potentially dangerous SQL keywords
    sql_keywords = [
        'select', 'insert', 'update', 'delete', 'drop', 'alter', 'create', 'exec', 
        'union', 'join', 'where', 'and', 'or', 'not', 'truncate', 'rename', 'table',
        'from', 'grant', 'revoke', 'commit', 'rollback', 'savepoint'
    ]

    # Check if any SQL keyword is present (case-insensitive, due to lowercase input)
    for keyword in sql_keywords:
        if keyword in lowered_input:  # Now comparing lowered input with lowercase keywords
            print(f"SQL injection keyword found: {keyword}")
            return True

    # Check for special characters typically used in SQL injection attacks
    dangerous_characters = [';', '--', '/*', '*/', '@@', '@', "'", '"', '\\', '%']

    # Check for any of these dangerous characters
    for char in dangerous_characters:
        if char in input_string:
            print(f"Dangerous character found: {char}")
            return True
    
    # No suspicious content detected
    return False

################################################################################
# Connect to the database
#   - This function reads the config file and tries to connect
#   - This is the main "connection" function used to set up our connection
################################################################################

def database_connect():
    # Read the config file
    config = configparser.ConfigParser()
    config.read('config.ini')

    # Create a connection to the database
    connection = None

    # choose a connection target, you can use the default or
    # use a different set of credentials that are setup for localhost or winhost
    connectiontarget = 'DATABASE'
    try:
        '''
        This is doing a couple of things in the back
        what it is doing is:

        connect(database='y2?i2120_unikey',
            host='awsprddbs4836.shared.sydney.edu.au,
            password='password_from_config',
            user='y2?i2120_unikey')
        '''
        targetdb = ""
        if ('database' in config[connectiontarget]):
            targetdb = config[connectiontarget]['database']
        else:
            targetdb = config[connectiontarget]['user']

        connection = pg8000.connect(database=targetdb,
                                    user=config[connectiontarget]['user'],
                                    password=config[connectiontarget]['password'],
                                    host=config[connectiontarget]['host'],
                                    port=int(config[connectiontarget]['port']))
        connection.run("SET SCHEMA 'airline';")
    except pg8000.OperationalError as e:
        print("""Error, you haven't updated your config.ini or you have a bad
        connection, please try again. (Update your files first, then check
        internet connection)
        """)
        print(e)
    except pg8000.ProgrammingError as e:
        print("""Error, config file incorrect: check your password and username""")
        print(e)
    except Exception as e:
        print(e)

    # Return the connection to use
    return connection

######################################
# Database Helper Functions
######################################
def dictfetchall(cursor,sqltext,params=[]):
    """ Returns query results as list of dictionaries."""
    """ Useful for read queries that return 1 or more rows"""

    result = []
    
    cursor.execute(sqltext,params)
    if cursor.description is not None:
        cols = [a[0] for a in cursor.description]
        
        returnres = cursor.fetchall()
        if returnres is not None or len(returnres > 0):
            for row in returnres:
                result.append({a:b for a,b in zip(cols, row)})
    return result

def dictfetchone(cursor,sqltext,params=None):
    """ Returns query results as list of dictionaries."""
    """ Useful for create, update and delete queries that only need to return one row"""

    result = []
    cursor.execute(sqltext,params)
    if (cursor.description is not None):
        print("cursor description", cursor.description)
        cols = [a[0] for a in cursor.description]
        returnres = cursor.fetchone()
        print("returnres: ", returnres)
        if (returnres is not None):
            result.append({a:b for a,b in zip(cols, returnres)})
    return result

##################################################
# Print a SQL string to see how it would insert  #
##################################################

def print_sql_string(inputstring, params=None):
    """
    Prints out a string as a SQL string parameterized assuming all strings
    """
    if params is not None:
        if params != []:
           inputstring = inputstring.replace("%s","'%s'")
    
    print(inputstring % params)

###############
# Login       #
###############

import bcrypt

import bcrypt

def check_login(username, password):
    '''
    Check login given a username and password.
    This function retrieves the user record and compares the entered password with the hashed password.
    '''
    # Ask for the database connection, and get the cursor set up
    conn = database_connect()
    print("checking login")

    if conn is None:
        return None

    cur = conn.cursor()
    try:
        # Fetch the user record by username (userid)
        sql = """SELECT Users.userid, Users.firstname, Users.lastname, Users.password AS hashed_pwd, 
                        UserRoles.userroleid, UserRoles.rolename, UserRoles.isadmin
                 FROM Users
                 JOIN UserRoles ON Users.userroleid = UserRoles.userroleid
                 WHERE Users.userid=%s"""
        print_sql_string(sql, (username,))
        r = dictfetchone(cur, sql, (username,))  # Fetch the first row (the user record)

        # Debug: Print the fetched result to check its structure
        print(f"Query result: {r}")
        
        # Check if any result was returned and extract the first item if it's a list
        if r is None:
            print("No user found for the given username.")
            return None  # User not found

        # Extract dictionary from list if needed
        if isinstance(r, list):
            r = r[0]  # Get the first dictionary from the list

        # Access the hashed password using the correct key (hashed_pwd)
        stored_pwd = r['hashed_pwd']  # Access the password using the dictionary key

        # Compare the entered password with the stored hashed password using bcrypt
        if bcrypt.checkpw(password.encode('utf-8'), stored_pwd.encode('utf-8')):
            print("Password match!")
            return r  # Password is correct, return user record
        else:
            print("Incorrect password.")
            return None  # Incorrect password

    except Exception as e:
        # If there were any errors, return None and print the error to the debug
        import traceback
        traceback.print_exc()
        print("Error Invalid Login")
        return None
    finally:
        cur.close()  # Close the cursor
        conn.close()  # Close the connection to the db

    
########################
#List All Items#
########################

# Get all the rows of users and return them as a dict
def list_users():
    # Get the database connection and set up the cursor
    conn = database_connect()
    if(conn is None):
        # If a connection cannot be established, send an Null object
        return None
    # Set up the rows as a dictionary
    cur = conn.cursor()
    returndict = None

    try:
        # Set-up our SQL query
        sql = """SELECT *
                    FROM users """
        
        # Retrieve all the information we need from the query
        returndict = dictfetchall(cur,sql)

        # report to the console what we recieved
        print(returndict)
    except:
        # If there are any errors, we print something nice and return a null value
        import traceback
        traceback.print_exc()
        print("Error Fetching from Database", sys.exc_info()[0])

    # Close our connections to prevent saturation
    cur.close()
    conn.close()

    # return our struct
    return returndict
    

def list_userroles():
    # Get the database connection and set up the cursor
    conn = database_connect()
    if(conn is None):
        # If a connection cannot be established, send an Null object
        return None
    # Set up the rows as a dictionary
    cur = conn.cursor()
    returndict = None

    try:
        # Set-up our SQL query
        sql = """SELECT *
                    FROM userroles """
        
        # Retrieve all the information we need from the query
        returndict = dictfetchall(cur,sql)

        # report to the console what we recieved
        print(returndict)
    except:
        # If there are any errors, we print something nice and return a null value
        print("Error Fetching from Database", sys.exc_info()[0])

    # Close our connections to prevent saturation
    cur.close()
    conn.close()

    # return our struct
    return returndict
    

########################
#List Single Items#
########################

# Get all rows in users where a particular attribute matches a value
def list_users_equifilter(attributename, filterval):
    # Get the database connection and set up the cursor
    conn = database_connect()
    if(conn is None):
        # If a connection cannot be established, send an Null object
        return None
    # Set up the rows as a dictionary
    cur = conn.cursor()
    val = None

    try:
        valid_columns = ['userid', 'firstname', 'lastname', 'userroleid']  # List of valid columns
        if attributename not in valid_columns:
            raise ValueError("Invalid attribute name.")
        # Retrieve all the information we need from the query
        sql = f"""SELECT *
                    FROM users
                    WHERE {attributename} = %s """
        val = dictfetchall(cur,sql,(filterval,))
    except:
        # If there are any errors, we print something nice and return a null value
        import traceback
        traceback.print_exc()
        print("Error Fetching from Database: ", sys.exc_info()[0])

    # Close our connections to prevent saturation
    cur.close()
    conn.close()

    # return our struct
    return val
    


########################### 
#List Report Items #
###########################
    
# # A report with the details of Users, Userroles
def list_consolidated_users():
    # Get the database connection and set up the cursor
    conn = database_connect()
    if(conn is None):
        # If a connection cannot be established, send an Null object
        return None
    # Set up the rows as a dictionary
    cur = conn.cursor()
    returndict = None

    try:
        # Set-up our SQL query
        sql = """SELECT *
                FROM users 
                    JOIN userroles 
                    ON (users.userroleid = userroles.userroleid) ;"""
        
        # Retrieve all the information we need from the query
        returndict = dictfetchall(cur,sql)

        # report to the console what we recieved
        print(returndict)
    except:
        # If there are any errors, we print something nice and return a null value
        print("Error Fetching from Database", sys.exc_info()[0])

    # Close our connections to prevent saturation
    cur.close()
    conn.close()

    # return our struct
    return returndict

def list_user_stats():
    # Get the database connection and set up the cursor
    conn = database_connect()
    if(conn is None):
        # If a connection cannot be established, send an Null object
        return None
    # Set up the rows as a dictionary
    cur = conn.cursor()
    returndict = None

    try:
        # Set-up our SQL query
        sql = """SELECT userroleid, COUNT(*) as count
                FROM users 
                    GROUP BY userroleid
                    ORDER BY userroleid ASC ;"""
        
        # Retrieve all the information we need from the query
        returndict = dictfetchall(cur,sql)

        # report to the console what we recieved
        print(returndict)
    except:
        # If there are any errors, we print something nice and return a null value
        print("Error Fetching from Database", sys.exc_info()[0])

    # Close our connections to prevent saturation
    cur.close()
    conn.close()

    # return our struct
    return returndict
    

####################################
##  Search Items - inexact matches #
####################################

# Search for users with a custom filter
# filtertype can be: '=', '<', '>', '<>', '~', 'LIKE'
def search_users_customfilter(attributename, filtertype, filterval):
    # Get the database connection and set up the cursor
    conn = database_connect()
    if(conn is None):
        # If a connection cannot be established, send an Null object
        return None

    # Set up the rows as a dictionary
    cur = conn.cursor()
    val = None

    # arrange like filter
    filtervalprefix = ""
    filtervalsuffix = ""
    if str.lower(filtertype) == "like":
        filtervalprefix = "'%"
        filtervalsuffix = "%'"
        
    try:
        valid_columns = ['userid', 'firstname', 'lastname', 'userroleid']  # Add valid column names here
        if attributename not in valid_columns:
            raise ValueError("Invalid attribute name.")
        # Retrieve all the information we need from the query
        sql = f"""SELECT *
                    FROM users
                    WHERE lower({attributename}) {filtertype} {filtervalprefix}lower(%s){filtervalsuffix} """
        print_sql_string(sql, (filterval,))
        val = dictfetchall(cur,sql,(filterval,))
    except:
        # If there are any errors, we print something nice and return a null value
        import traceback
        traceback.print_exc()
        print("Error Fetching from Database: ", sys.exc_info()[0])

    # Close our connections to prevent saturation
    cur.close()
    conn.close()

    # return our struct
    return val


#####################################
##  Update Single Items by PK       #
#####################################
# Update a single user
def update_single_user(userid, firstname=None, lastname=None, userroleid=None, password=None):
    # Get the database connection and set up the cursor
    conn = database_connect()
    if conn is None:
        # If a connection cannot be established, send a None object
        return None

    cur = conn.cursor()
    
    # Data validation checks are assumed to have been done in route processing
    try:
        # Create a dynamic set of columns to update based on the provided fields
        setitems = []
        values = []

        if firstname is not None:
            setitems.append("firstname = %s")
            values.append(firstname)

        if lastname is not None:
            setitems.append("lastname = %s")
            values.append(lastname)

        if userroleid is not None:
            setitems.append("userroleid = %s::bigint")
            values.append(userroleid)

        if password is not None:
            setitems.append("password = %s")
            values.append(password)

        # Ensure there is something to update
        if len(setitems) == 0:
            print("No fields to update")
            return None
        
        # Add the userid as the final value for the WHERE clause
        values.append(userid)

        # Build the SQL query dynamically
        sql = f"UPDATE users SET {', '.join(setitems)} WHERE userid = %s"
        
        # Execute the query using parameterized query to prevent SQL injection
        cur.execute(sql, tuple(values))

        # Commit the transaction
        conn.commit()

        # Optional: You can fetch and return the number of rows affected
        updated_rows = cur.rowcount  # Check how many rows were updated
        
    except Exception as e:
        # If there are any errors, rollback the transaction and print the error
        conn.rollback()
        print("Error updating the user in the database:", str(e))
        updated_rows = None

    # Close the cursor and the connection to free resources
    cur.close()
    conn.close()

    return updated_rows



##  Insert / Add

def add_user_insert(userid, firstname, lastname,userroleid,password):
    """
    Add a new User to the system
    """
    # Data validation checks are assumed to have been done in route processing

    conn = database_connect()
    if(conn is None):
        return None
    cur = conn.cursor()
    sql = """
        INSERT into Users(userid, firstname, lastname, userroleid, password)
        VALUES (%s,%s,%s,%s,%s);
        """
    print_sql_string(sql, (userid, firstname, lastname,userroleid,password))
    try:
        # Try executing the SQL and get from the database

        cur.execute(sql,(userid, firstname, lastname,userroleid,password))
        
        # r = cur.fetchone()
        r=[]
        conn.commit()                   # Commit the transaction
        print("return val is:")
        print(r)
        cur.close()                     # Close the cursor
        conn.close()                    # Close the connection to the db
        return r
    except:
        # If there were any errors, return a NULL row printing an error to the debug
        print("Unexpected error adding a user:", sys.exc_info()[0])
        cur.close()                     # Close the cursor
        conn.close()                    # Close the connection to the db
        raise

##  Delete
###     delete_user(userid)
def delete_user(userid):
    """
    Remove a user from your system
    """
    # Data validation checks are assumed to have been done in route processing
    conn = database_connect()
    if(conn is None):
        return None
    cur = conn.cursor()
    try:
        sql = "DELETE FROM users WHERE userid = %s"
        cur.execute(sql, (userid,))

        conn.commit()                   # Commit the transaction
        r = []
        # r = cur.fetchone()
        # print("return val is:")
        # print(r)
        cur.close()                     # Close the cursor
        conn.close()                    # Close the connection to the db
        return r
    except:
        # If there were any errors, return a NULL row printing an error to the debug
        print("Unexpected error deleting  user with id ",userid, sys.exc_info()[0])
        cur.close()                     # Close the cursor
        conn.close()                    # Close the connection to the db
        raise

########################### 
# Passengers table        #
###########################

# Show all passengers
def show_all_passengers(limit=40, offset=0):
    # Get the database connection and set up the cursor
    conn = database_connect()
    if conn is None:
        # If a connection cannot be established, send a Null object
        return None

    # Set up the rows as a dictionary
    cur = conn.cursor()
    passengers = None

    try:
        # Using LIMIT and OFFSET for pagination
        sql = "SELECT * FROM passengers LIMIT %s OFFSET %s"
        passengers = dictfetchall(cur, sql, (limit, offset))  # Passing the cursor, query, and params to dictfetchall
    except Exception as e:
        # If there are any errors, we print the error and return a null value
        import traceback
        traceback.print_exc()
        print(f"Error Fetching from Database: {e}")

    # Close our connections to prevent saturation
    cur.close()
    conn.close()

    # return our struct
    return passengers


def get_total_passenger_count():
    # Get the database connection and set up the cursor
    conn = database_connect()
    if conn is None:
        # If a connection cannot be established, return 0
        return 0

    cur = conn.cursor()
    total_count = 0

    try:
        # SQL query to count the total number of passengers
        sql = "SELECT COUNT(*) FROM passengers"
        cur.execute(sql)
        total_count = cur.fetchone()[0]  # Fetch the first result from the query

        # report to the console what we received
        print(f"Total passengers: {total_count}")
    except:
        # If there are any errors, print the error and return 0
        import traceback
        traceback.print_exc()
        print("Error Fetching from Database", sys.exc_info()[0])
    finally:
        # Close our connections to prevent saturation
        cur.close()
        conn.close()

    # return the total count of passengers
    return total_count

# get passengers nationalities
def get_passenger_nationality_summary():
    """
     display a summary of the various nationalities along with the number of passengers for each nationality
    """
    # Get the database connection and set up the cursor
    conn = database_connect()
    if conn is None:
        # If a connection cannot be established, return None
        return None

    cur = conn.cursor()
    nationality_summary = None

    try:
        # Query to count the number of passengers for each nationality
        sql = """
            SELECT nationality, COUNT(*) as num_passengers
            FROM passengers
            GROUP BY nationality
            ORDER BY nationality, num_passengers DESC;
        """
        cur.execute(sql)
        nationality_summary = cur.fetchall()
    except:
        import traceback
        traceback.print_exc()
        print("Error fetching nationality summary", sys.exc_info()[0])
    finally:
        # Close connections
        cur.close()
        conn.close()

    return nationality_summary

# search - Passenger retreive passenger using passengerID
def get_passenger_by_id(passenger_id):
    # Ensure passenger_id is an integer
    try:
        passenger_id = int(passenger_id)
    except ValueError:
        print("Invalid passenger ID: not an integer")
        return None
    
    # Get the database connection
    conn = database_connect()
    if conn is None:
        return None
    
    cur = conn.cursor()
    passenger = None

    try:
        # Parameterized query to prevent SQL injection
        sql = "SELECT * FROM passengers WHERE passengerid = %s"
        cur.execute(sql, (passenger_id,))
        passenger = cur.fetchone()  # Fetch one passenger record

        print("Passenger query result:", passenger)  # For debugging

    except Exception as e:
        print(f"Error fetching passenger: {e}")
    
    finally:
        cur.close()  # Ensure the cursor and connection are always closed
        conn.close()

    return passenger


# Search passengers with a selected fields
def search_passenger_by_field(search_field, search_value):
    """
    Search for passengers in the database by a specific field.
    :param search_field: The field to search by (e.g., 'firstname', 'lastname').
    :param search_value: The value to search for.
    :return: A list of passengers matching the criteria.
    """
    conn = database_connect()
    if conn is None:
        return []

    cur = conn.cursor()
    passengers = []

    try:
        # Validate the search field to prevent SQL injection.
        valid_fields = ['passengerid', 'firstname', 'lastname', 'dateofbirth', 'nationality', 'passportnumber']
        if search_field not in valid_fields:
            print(f"Invalid search field: {search_field}")
            return []

        # Check if the field is a string or numeric type, and modify the SQL query accordingly
        if search_field in ['firstname', 'lastname', 'nationality', 'passportnumber']:
            # Use LOWER() for string-based fields
            sql = f"SELECT * FROM passengers WHERE LOWER({search_field}) = LOWER(%s)"
        else:
            # Do not use LOWER() for non-string fields
            sql = f"SELECT * FROM passengers WHERE {search_field} = %s"

        cur.execute(sql, (search_value,))
        passengers = dictfetchall(cur, sql, (search_value,))

        # Ensure the result is a list
        if passengers and not isinstance(passengers, list):
            passengers = [passengers]

        print("Search query result:", passengers)

    except Exception as e:
        print(f"Error searching for passenger: {e}")

    finally:
        cur.close()
        conn.close()

    return passengers

# add a passenger 
def add_passenger_insert(passenger_id, first_name, last_name, dob, gender, nationality, passport_number):
    """
    Add a new Passenger to the system
    """
    # Connect to the database
    conn = database_connect()
    if conn is None:
        return None

    cur = conn.cursor()

    # SQL Insert Query
    sql = """
        INSERT INTO passengers (passengerid, firstname, lastname, dateofbirth, gender, nationality, passportnumber)
        VALUES (%s, %s, %s, %s, %s, %s, %s);
    """
    
    print_sql_string(sql, (passenger_id, first_name, last_name, dob, gender, nationality, passport_number))

    try:
        # Execute the SQL statement
        cur.execute(sql, (passenger_id, first_name, last_name, dob, gender, nationality, passport_number))
        conn.commit()  # Commit the transaction
        print("Passenger added successfully.")
        return True
        
    except Exception as e:
        # Rollback the transaction in case of any errors
        conn.rollback()
        print(f"Error adding passenger: {e}")  
        return False

    finally:
        cur.close()  # Close the cursor
        conn.close()  # Close the connection

# Check if passenger has a ticket 
def is_passenger_associated_with_tickets(passenger_id):
    """
    Checks if the passenger is associated with any tickets.
    Returns True if there are tickets associated, False otherwise.
    """
    conn = database_connect() 
    if conn is None:
        return False
    
    cur = conn.cursor()
    try:
        # Check if the passenger ID is being used in the tickets table
        sql = "SELECT COUNT(*) FROM tickets WHERE passengerid = %s"
        cur.execute(sql, (passenger_id,))
        count = cur.fetchone()[0]

        if count > 0:
            print(f"Passenger ID {passenger_id} is associated with {count} ticket(s).")
            return True
        else:
            return False
    except Exception as e:
        print(f"Error checking tickets for passenger {passenger_id}: {e}")
        return False
    finally:
        cur.close()
        conn.close()


# delete passenger 
def delete_passenger(passenger_id):
    """
    Delete a passenger from the database by passengerid, but first check if they are used in tickets.
    """
    
    conn = database_connect() 
    if conn is None:
        return False
    
    cur = conn.cursor()
    try:  
        # Proceed with the deletion after checking if they have no associated tickets
        sql = "DELETE FROM passengers WHERE passengerid = %s"
        cur.execute(sql, (passenger_id,))
        conn.commit()  # Commit the transaction after successful deletion
        print(f"Passenger ID {passenger_id} deleted successfully.")
        return True
    except Exception as e:
        conn.rollback()  # Rollback the transaction in case of an error
        print(f"Error deleting passenger: {e}")  # Log the error (but don't expose it to users)
        return False
    finally:
        cur.close()
        conn.close()

# Update passenger
def update_passenger(old_passengerid, new_passengerid, firstname, lastname, dateofbirth, gender, nationality, passportnumber):
    """
    Update the passenger's details in the database, including changing the passenger ID.
    :param old_passengerid: Existing passenger ID
    :param new_passengerid: New passenger ID (can be the same as old_passengerid)
    :param firstname: New first name
    :param lastname: New last name
    :param dateofbirth: New date of birth
    :param gender: New gender (M/F)
    :param nationality: New nationality
    :param passportnumber: New passport number
    :return: True if successful, False otherwise
    """
    conn = database_connect()
    if conn is None:
        return False

    cur = conn.cursor()

    try:
     # Check if passenger_id is being updated and if it is associated with tickets
        if new_passengerid != old_passengerid:
            # Check if the current passenger ID is associated with any tickets
            if is_passenger_associated_with_tickets(old_passengerid):
                raise ValueError("Cannot update Passenger ID because it is associated with tickets.")
        
        # Check if the new passenger ID is already taken
        if old_passengerid != new_passengerid:
            sql = "SELECT passengerid FROM passengers WHERE passengerid = %s"
            cur.execute(sql, (new_passengerid,))
            if cur.fetchone() is not None:
                raise ValueError("The new Passenger ID is already in use.")

        # Update the passenger details, including the passenger ID
        query = """
            UPDATE passengers 
            SET passengerid = %s, firstname = %s, lastname = %s, dateofbirth = %s, gender = %s, nationality = %s, passportnumber = %s
            WHERE passengerid = %s
        """
        cur.execute(query, (new_passengerid, firstname, lastname, dateofbirth, gender, nationality, passportnumber, old_passengerid))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating passenger: {e}")
        return False
    finally:
        cur.close()
        conn.close()

# Extension slim0093
def get_passenger_ticket_summary_paginated(limit=40, offset=0):
    """
    Retrieve the ticket count for each passenger from the PassengerTicketSummary table, with pagination
    """
    conn = database_connect()  # Establish the database connection
    if conn is None:
        return None

    try:
        cur = conn.cursor()
        # Query to get the ticket count with LIMIT and OFFSET for pagination
        query = """
            SELECT PassengerID, FirstName, LastName, TicketCount
            FROM PassengerTicketSummary
            ORDER BY PassengerID
            LIMIT %s OFFSET %s;

        """
        cur.execute(query, (limit, offset))
        result = cur.fetchall()
        cur.close()
        conn.close()

        # Return the result as a list of dictionaries
        return [{'PassengerID': row[0], 'FirstName': row[1], 'LastName': row[2], 'TicketCount': row[3]} for row in result]
    
    except Exception as e:
        print(f"Error retrieving paginated passenger ticket summary: {e}")
        return None

# Extension
def search_passenger_by_id(passenger_id):
    """
    Search for a passenger by PassengerID in the PassengerTicketSummary table.
    """
    conn = database_connect()  # Establish the database connection
    if conn is None:
        return None

    try:
        cur = conn.cursor()
        # Query to search for the passenger by PassengerID
        query = """
            SELECT PassengerID, FirstName, LastName, TicketCount
            FROM PassengerTicketSummary
            WHERE PassengerID = %s;
        """
        cur.execute(query, (passenger_id,))
        result = cur.fetchone()  # Fetch only one row since we are searching by PassengerID
        cur.close()
        conn.close()

        # Return the result as a dictionary
        if result:
            return {
                'PassengerID': result[0],
                'FirstName': result[1],
                'LastName': result[2],
                'TicketCount': result[3]
            }
        else:
            return None
    
    except Exception as e:
        print(f"Error searching for passenger by ID: {e}")
        return None
