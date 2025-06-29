# AirlineBookingApp
A full-stack airline reservation system built with Flask and PostgreSQL, featuring secure user authentication and real-time booking interactions.

## Tech Stack
- Python (Flask)
- PostgreSQL
- HTML/CSS/JS (Bootstrap)
- SQL (joins, filters, subqueries)

## Features
- User registration and login with bcrypt password hashing
- Flight search and booking functionality
- Secure session handling with Flask server-side sessions
- PostgreSQL queries using pg8000
- Responsive frontend (Bootstrap-based)

## Structure
- database.py – handles SQL queries and DB connection
- routes.py – manages app logic and routing
- web_app.py – entry point to run the app
- static/ – CSS/JS files
- templates/ – HTML pages

## How to Run
1. Clone the repo

2. cd into `airline-webapp`

3. Install dependencies: 
```bash 
pip install -r requirements.txt
```

4. Set up PostgreSQL and update config.ini

5. In terminal, run: 
```bash
python web_app.py
```

