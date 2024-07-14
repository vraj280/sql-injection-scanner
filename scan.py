import streamlit as st
import requests
from bs4 import BeautifulSoup
import sqlite3

# Create/connect to SQLite database
conn = sqlite3.connect('sqlguard.db')
c = conn.cursor()

# Create table for user credentials if not exists
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)''')

# Membership table
c.execute('''CREATE TABLE IF NOT EXISTS memberships
             (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, plan TEXT)''')

# Payment table
c.execute('''CREATE TABLE IF NOT EXISTS payments
             (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, amount REAL, payment_date TEXT)''')

# Wallet table
c.execute('''CREATE TABLE IF NOT EXISTS wallets
             (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, balance REAL)''')

# Scan table
c.execute('''CREATE TABLE IF NOT EXISTS scans
             (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, url TEXT, scan_date TEXT, scan_count INTEGER DEFAULT 0,
                FOREIGN KEY (username) REFERENCES users(username))''')

# Login function
def login(username, password):
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = c.fetchone()
    return user is not None

# Register function
def register(username, password):
    if username.strip() and password.strip():
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        existing_user = c.fetchone()
        if existing_user:
            return False, "Username already exists. Please choose a different username."
        else:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            return True, "User registered successfully."
    else:
        return False, "Username or password cannot be empty."

# Membership registration function
def register_membership(username, plan):
    c.execute("INSERT INTO memberships (username, plan) VALUES (?, ?)", (username, plan))
    conn.commit()
    return True, "Membership registered successfully."

# Add money to wallet function
def add_to_wallet(username, amount):
    c.execute("SELECT * FROM wallets WHERE username=?", (username,))
    wallet = c.fetchone()
    if wallet:
        new_balance = wallet[2] + amount
        c.execute("UPDATE wallets SET balance=? WHERE username=?", (new_balance, username))
    else:
        c.execute("INSERT INTO wallets (username, balance) VALUES (?, ?)", (username, amount))
    conn.commit()

# Process payment function
def process_payment(username, amount):
    c.execute("SELECT * FROM wallets WHERE username=?", (username,))
    wallet = c.fetchone()
    if wallet and wallet[2] >= amount:
        new_balance = wallet[2] - amount
        c.execute("UPDATE wallets SET balance=? WHERE username=?", (new_balance, username))
        conn.commit()
        return True
    else:
        return False

# Check if user is a member
def is_member(username):
    c.execute("SELECT * FROM memberships WHERE username=?", (username,))
    membership = c.fetchone()
    return membership is not None

# Check if user has already scanned for free
def has_scanned_free(username):
    c.execute("SELECT * FROM scans WHERE username=?", (username,))
    scan = c.fetchone()
    return scan is not None

# Get HTML forms from URL
def get_forms(url):
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, "html.parser")
        forms = soup.find_all("form")
        return forms
    else:
        return []

# Extract form details
def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type, 
            "name" : input_name,
            "value" : input_value,
        })

    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

# Check if response indicates vulnerability
def vulnerable(response):
    errors = {"quoted string not properly terminated", 
              "unclosed quotation mark after the charachter string",
              "you have an error in you SQL syntax" 
             }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

# Perform SQL injection scan
def sql_injection_scan(url, username, scan_depth=5, custom_payloads=None):
    forms = get_forms(url)
    num_forms_detected = len(forms)

    vulnerability_status = 'N'

    for form in forms:
        details = form_details(form)

        res = None

        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"

            if details["method"] == "post":
                res = requests.post(url, data=data)
            elif details["method"] == "get":
                res = requests.get(url, params=data)

            if res is not None and vulnerable(res):
                vulnerability_status = 'V'
                break
    
    c.execute("INSERT INTO scans (username, url, scan_date) VALUES (?, ?, date('now'))", (username, url))
    conn.commit()

    return num_forms_detected, vulnerability_status

# Streamlit app

import streamlit as st

# Define custom CSS styles
custom_css = """
<style>
/* Custom CSS for SQL Injection theme */
body {
    font-family: Arial, sans-serif;
    background-color: #f8f9fa; /* Light background */
    color: #333; /* Dark text color */
}

.sidebar .sidebar-content {
    background-color: #343a40; /* Dark sidebar background */
    color: #fff; /* Light text color */
}

.stButton>button {
    background-color: #007bff; /* Primary button color */
    color: #fff; /* Button text color */
    border-color: #007bff; /* Button border color */
}

.stButton>button:hover {
    background-color: #0056b3; /* Button hover color */
    color: #fff; /* Button text color */
    border-color: #0056b3; /* Button border color */
}

.stTextInput>div>div>input {
    background-color: #fff; /* Text input background color */
    color: #495057; /* Text input text color */
    border-color: #ced4da; /* Text input border color */
}

.stTextInput>div>div>input:focus {
    background-color: #fff; /* Text input background color on focus */
    color: #495057; /* Text input text color on focus */
    border-color: #80bdff; /* Text input border color on focus */
}

.stTextArea>div>textarea {
    background-color: #fff; /* Text area background color */
    color: #495057; /* Text area text color */
    border-color: #ced4da; /* Text area border color */
}

.stTextArea>div>textarea:focus {
    background-color: #fff; /* Text area background color on focus */
    color: #495057; /* Text area text color on focus */
    border-color: #80bdff; /* Text area border color on focus */
}

.stSlider>div>div>div>input {
    background-color: #fff; /* Slider background color */
}

.stSlider>div>div>div>input::-webkit-slider-thumb {
    background-color: #007bff; /* Slider thumb color */
}

.stSlider>div>div>div>input::-moz-range-thumb {
    background-color: #007bff; /* Slider thumb color */
}

.stTable {
    background-color: #fff; /* Table background color */
    color: #333; /* Table text color */
}

.stTable th {
    background-color: #343a40; /* Table header background color */
    color: #fff; /* Table header text color */
}

.stTable td, .stTable th {
    border: 1px solid #dee2e6; /* Table border color */
    padding: .75rem; /* Table cell padding */
}

.stSuccess {
    color: #28a745; /* Success message color */
}

.stError {
    color: #dc3545; /* Error message color */
}

.stWarning {
    color: #ffc107; /* Warning message color */
}
</style>
"""

# Apply custom theme
st.markdown(custom_css, unsafe_allow_html=True)

# Your Streamlit app code goes here



def main():
    conn = sqlite3.connect("sqlguard.db")
    st.title("SQL Injection Vulnerability Scanner")

    if 'is_authenticated' not in st.session_state:
        st.session_state.is_authenticated = False

    page = st.sidebar.selectbox("Select Page", ["Login", "Register", "Scan", "Membership", "Payment", "SQL Injection Lab", "Tutorial", "Glossary", "Leaderboard", "History", "Settings"])
    
    if page == "Login":
        login_page()
    elif page == "Register":
        register_page()
    elif page == "Membership":
        membership_page()
    elif page == "Payment":
        payment_page()
    elif page == "Scan":
        main_page()
    elif page == "SQL Injection Lab":
        lab_page()
    elif page == "Tutorial":
        tutorial_page()
    elif page == "Glossary":
        glossary_page()
    elif page == "Leaderboard":
        leaderboard_page()
    elif page == "History":
        history_page()
    elif page == "Settings":
        settings_page()


        

def login_page():
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if login(username, password):
            st.session_state.username = username
            st.session_state.is_authenticated = True
            st.success("Login successful.")
        else:
            st.error("Invalid username or password. Please try again.")

def register_page():
    st.title("Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        success, message = register(username, password)
        if success:
            st.session_state.is_authenticated = True
            st.success(message)
        else:
            st.error(message)

def register_membership(username, plan):
    try:
        conn = sqlite3.connect("/Users/vrajpatel/Desktop/scopy/sqlguard.db")
        cursor = conn.cursor()

        # Check if the username already exists in the memberships table
        cursor.execute("SELECT * FROM memberships WHERE username=?", (username,))
        existing_membership = cursor.fetchone()

        if existing_membership:
            return False, "Username already registered for membership."

        # Insert the new membership record
        cursor.execute("INSERT INTO memberships (username, plan) VALUES (?, ?)", (username, plan))
        conn.commit()
        conn.close()

        return True, "Membership registration successful."
    except Exception as e:
        return False, f"Error registering membership: {str(e)}"

def membership_page():
    def membership_page():
     st.title("Membership Registration")
    username = st.text_input("Username")
    plan = st.selectbox("Select Membership Plan", ["Basic", "Premium", "Pro"])
    if st.button("Register Membership"):
        success, message = register_membership(username, plan)
        if success:
            st.success(message)
            # Update is_member_status after successful registration
            st.session_state.is_member_status = True
        else:
            st.error(message)
            # Set is_member_status to False if registration fails
            st.session_state.is_member_status = False


def is_member(username):
    try:
                 
        conn = sqlite3.connect("/Users/vrajpatel/Desktop/scopy/sqlguard.db")
        cursor = conn.cursor()

            # Check if the user is a member
        cursor.execute("SELECT * FROM memberships WHERE username=?", (username,))
        membership = cursor.fetchone()

        conn.close()
        return membership is not None
    except Exception as e:
        print(f"Error checking membership: {str(e)}")
        return False

def main_page():
    st.title("Main Page")
    if "username" not in st.session_state:
        st.warning("Please login to access this page.")
        return

    username = st.session_state.username
        
    # Check if the user is a member
    is_member_status = is_member(username)

    # Restrict non-members from scanning more than once
    if not is_member_status:
        if "scans_remaining" not in st.session_state:
            st.session_state.scans_remaining = 1
        elif st.session_state.scans_remaining == 0:
            st.warning("Upgrade to a membership plan to unlock unlimited scans.")
            return

    # Retrieve wallet balance if the user is not a member
    
   

    url = st.text_input("Enter URL to check for SQL injection vulnerability")
    scan_depth = st.slider("Scan Depth", min_value=1, max_value=10, value=5)
    custom_payloads = st.text_area("Custom Payloads (one per line)")
    num_forms_detected = 0  # Initialize num_forms_detected here
    vulnerability_status = ""  # Initialize vulnerability_status here

    if st.button("Scan", key="scan_button"):
        with st.spinner("Scanning in progress..."):
            try:
                # Acquire the lock before accessing the database
              

                # Perform SQL injection scan
                num_forms_detected, vulnerability_status = sql_injection_scan(url, username, scan_depth, custom_payloads)
                st.success("Scan completed!")

                # Display scan results
                st.write(f"\nNumber of forms detected: {num_forms_detected}")
                st.write(f"Vulnerability Status: {vulnerability_status}")
                st.write(f"- Overall Vulnerability Status: {'Vulnerable' if vulnerability_status == 'V' else 'Not Vulnerable'}")

                # Export report, schedule scan, etc.
                if st.button("Export Report", key="export_report_button"):
                    export_report(num_forms_detected, vulnerability_status)

                if st.button("Schedule Scan", key="schedule_scan_button"):
                    schedule_scan(url, scan_depth, custom_payloads)

                # Decrement scans_remaining for non-members
                if not is_member_status:
                    st.session_state.scans_remaining -= 1
            except Exception as e:
                st.error(f"Error during scanning: {str(e)}")
          
                # Release the lock after accessing the database
                

def export_report(num_forms_detected, vulnerability_status):
    with open("scan_report.txt", "w") as file:
        file.write(f"Number of forms detected: {num_forms_detected}\n")
        file.write(f"Vulnerability Status: {vulnerability_status}\n")
    st.success("Report exported successfully!")

def schedule_scan(url, scan_depth, custom_payloads):
    with st.spinner("Scheduling scan..."):
        num_forms_detected, vulnerability_status = sql_injection_scan(url, st.session_state.username, scan_depth, custom_payloads)
        export_report(num_forms_detected, vulnerability_status)
    st.success("Scan scheduled successfully!")


def lab_page():
    st.title("SQL Injection Lab")
    st.markdown("Welcome to the SQL Injection Lab! Here you can practice SQL injection on vulnerable web forms.")
    st.markdown("Select a lab exercise from the list below.")

    # Define lab exercises with their URLs
    lab_exercises = {
        "Exercise 1 (SQL Injection Demo)": "http://localhost:8000/index.php",
        "Exercise 2": "http://example.com/vulnerable_form2",
        # Add more exercises as needed
    }

    selected_lab = st.selectbox("Select Lab Exercise", list(lab_exercises.keys()))

    if selected_lab == "Exercise 1 (SQL Injection Demo)":
        st.markdown("This is a vulnerable login form susceptible to SQL injection. Follow the tutorial below to learn how to exploit it.")

        # Embed the vulnerable login form using an iframe
        st.write('<iframe src="http://localhost:8000/index.php" width="100%" height="500"></iframe>', unsafe_allow_html=True)

        # Provide feedback and guidance
        st.markdown("**Tutorial:**")
        st.markdown("- Step 1: Enter a valid username.")
        st.markdown("- Step 2: Enter a SQL injection payload in the password field.")
        st.markdown("- Step 3: Observe the response to see if you can bypass authentication.")
        st.markdown("**Hints:**")
        st.markdown("- Try entering `' OR '1'='1` as the password to bypass authentication.")
        st.markdown("- Experiment with different SQL injection payloads to understand their impact.")
        st.markdown("**Feedback:**")
        st.markdown("Once you successfully bypass authentication, you will be redirected to the home page.")

    elif selected_lab == "Exercise 2":
        st.write("Exercise 2 URL:", lab_exercises[selected_lab])
        st.write("This is the vulnerable web form for Exercise 2.")
        st.write("Provide instructions and hints here to guide students.")
        st.write("You can also embed the form directly here using an iframe.")

        # Implement reward system
        reward_claimed = st.button("Claim Reward")
        if reward_claimed:
            st.success("Congratulations! You have successfully completed Exercise 2. Here's your reward.")

    else:
        st.write("Select an exercise to view the vulnerable web form.")



def tutorial_page():
    st.title("SQL Injection Tutorial")
    st.markdown("SQL Injection is a technique used to attack data-driven applications by inserting malicious SQL code into input fields.")
    st.markdown("To learn more about SQL Injection, you can refer to online resources and tutorials available on various websites.")

    st.header("Step 1: Identify the Vulnerable Input Field")
    st.write("First, identify the input field where SQL injection can be attempted.")
    st.write("In this example, let's consider a login form with a username and password field.")

    # Animation for identifying input field
    st.markdown('<div style="position:relative;height:0;padding-bottom:56.25%"><iframe src="https://giphy.com/embed/9JthKvaB1wW59xqh6S" width="480" height="270" style="position:absolute;width:100%;height:100%;left:0" frameborder="0" allowfullscreen></iframe></div>', unsafe_allow_html=True)

    st.header("Step 2: Attempt SQL Injection")
    st.write("Inject SQL code into the input field to bypass authentication.")
    st.write("For example, try entering 'admin' as the username and 'OR 1=1 --' as the password.")

    # Animation for injecting SQL code
    st.markdown('<div style="position:relative;height:0;padding-bottom:56.25%"><iframe src="https://giphy.com/embed/xTiTnh3qs14J1Ov4ha" width="480" height="270" style="position:absolute;width:100%;height:100%;left:0" frameborder="0" allowfullscreen></iframe></div>', unsafe_allow_html=True)

    st.header("Step 3: Analyze Response")
    st.write("Observe the system's response to the injected SQL code.")
    st.write("If the system responds differently or grants unauthorized access, the injection was successful.")

    # Animation for analyzing response
    st.markdown('<div style="position:relative;height:0;padding-bottom:56.25%"><iframe src="https://giphy.com/embed/3o6Zt8oTYchUnyZTg8" width="480" height="270" style="position:absolute;width:100%;height:100%;left:0" frameborder="0" allowfullscreen></iframe></div>', unsafe_allow_html=True)

def glossary_page():
    st.title("SQL Injection Glossary")

    st.markdown("**SQL Injection**: SQL Injection is a code injection technique that exploits a security vulnerability in an application's software.")
    st.markdown("**Vulnerable Web Form**: A web form that is susceptible to SQL Injection attacks due to improper handling of user input.")
    st.markdown("**Payload**: The malicious SQL code that is injected into the vulnerable web form to exploit the SQL Injection vulnerability.")

    st.markdown("## Explanation")

    st.markdown(
        """SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. This can allow an attacker to view data that they are not normally able to retrieve. This might include data that belongs to other users, or any other data that the application can access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

        In some situations, an attacker can escalate a SQL injection attack to compromise the underlying server or other back-end infrastructure. It can also enable them to perform denial-of-service attacks."""
    )

    st.markdown(
        """A successful SQL injection attack can result in unauthorized access to sensitive data, such as:

        - Passwords.
        - Credit card details.
        - Personal user information.

        SQL injection attacks have been used in many high-profile data breaches over the years. These have caused reputational damage and regulatory fines. In some cases, an attacker can obtain a persistent backdoor into an organization's systems, leading to a long-term compromise that can go unnoticed for an extended period."""
    )

    st.markdown(
        """You can detect SQL injection manually using a systematic set of tests against every entry point in the application. To do this, you would typically submit:

        - The single quote character `'` and look for errors or other anomalies.
        - Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the application responses.
        - Boolean conditions such as `OR 1=1` and `OR 1=2`, and look for differences in the application's responses.
        - Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.
        - OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.

        Alternatively, you can find the majority of SQL injection vulnerabilities quickly and reliably using Burp Scanner."""
    )

    st.markdown(
        """Most SQL injection vulnerabilities occur within the `WHERE` clause of a `SELECT` query. Most experienced testers are familiar with this type of SQL injection.

        However, SQL injection vulnerabilities can occur at any location within the query, and within different query types. Some other common locations where SQL injection arises are:

        - In `UPDATE` statements, within the updated values or the `WHERE` clause.
        - In `INSERT` statements, within the inserted values.
        - In `SELECT` statements, within the table or column name.
        - In `SELECT` statements, within the `ORDER BY` clause."""
    )

    st.markdown(
        """There are lots of SQL injection vulnerabilities, attacks, and techniques, that occur in different situations. Some common SQL injection examples include:

        - [Retrieving hidden data](https://example.com/web-security/sql-injection#retrieving-hidden-data), where you can modify a SQL query to return additional results.
        - [Subverting application logic](https://example.com/web-security/sql-injection#subverting-application-logic), where you can change a query to interfere with the application's logic.
        - [UNION attacks](https://example.com/web-security/sql-injection/union-attacks), where you can retrieve data from different database tables.
        - [Blind SQL injection](https://example.com/web-security/sql-injection/blind), where the results of a query you control are not returned in the application's responses."""
    )

    st.markdown(
        """Imagine a shopping application that displays products in different categories. When the user clicks on the **Gifts** category, their browser requests the URL:

        ```
        https://insecure-website.com/products?category=Gifts
        ```

        This causes the application to make a SQL query to retrieve details of the relevant products from the database:

        ```
        SELECT * FROM products WHERE category = 'Gifts' AND released = 1
        ```

        This SQL query returns all products that are in the **Gifts** category and have been released. Suppose that the application's developers have made a mistake and directly inserted the value of the `category` parameter into the SQL query without proper sanitization. In that case, you could modify the request to:

        ```
        https://insecure-website.com/products?category=Gifts' OR '1' = '1
        ```

        This would cause the SQL query to become:

        ```
        SELECT * FROM products WHERE category = 'Gifts' OR '1' = '1' AND released = 1
        ```

        Because `'1' = '1'` always evaluates to `true`, this SQL query returns all products from the **Gifts** category, regardless of whether they have been released. You have successfully retrieved data that was not intended to be visible."""
    )

    st.markdown(
        """Imagine that a bank application uses the following SQL query to check whether a user's credentials are correct:

        ```
        SELECT * FROM users WHERE username = '<input_username>' AND password = '<input_password>'
        ```

        Suppose that the application uses this SQL query to verify the user's credentials when they try to log in. If you can control the value of the `input_username` and `input_password` parameters, you might be able to log in without knowing the correct password by setting the value of the `input_password` parameter to:

        ```
        ' OR '1' = '1
        ```

        This would cause the SQL query to become:

        ```
        SELECT * FROM users WHERE username = '<input_username>' AND password = '' OR '1' = '1'
        ```

        Because `'1' = '1'` always evaluates to `true`, this SQL query returns the details of the first user in the database, regardless of the value of their password. You have successfully subverted the application's logic and bypassed the authentication mechanism."""
    )

    st.markdown(
        """Suppose that a website displays the user's search query in the search results page's URL, as shown below:

        ```
        https://insecure-website.com/search?q=banana
        ```

        The application retrieves the search results from the database using the following SQL query:

        ```
        SELECT * FROM products WHERE name LIKE '%banana%'
        ```

        This SQL query returns all products whose name contains the string `banana`. If the application is vulnerable to SQL injection and you can control the value of the `q` parameter, you might be able to retrieve data from a different table by submitting:

        ```
        https://insecure-website.com/search?q=banana' UNION SELECT NULL, username || '~' || password FROM users--
        ```

        This would cause the SQL query to become:

        ```
        SELECT * FROM products WHERE name LIKE '%banana%' UNION SELECT NULL, username || '~' || password FROM users--
        ```

        This SQL query returns all products whose name contains the string `banana`, plus all usernames and passwords from the `users` table. You have successfully retrieved data from a different table using a UNION attack."""
    )

    st.markdown(
        """Blind SQL injection arises when an application is vulnerable to SQL injection, but its responses do not contain the results of the relevant SQL query in the application's responses. In many cases, you can still retrieve the results of the SQL query indirectly, by triggering conditional statements within the SQL query that cause differences in the application's responses."""
    )

    st.markdown(
        """To prevent SQL injection, you should use parameterized queries (prepared statements) instead of string concatenation within the query. Parameterized queries prevent user input from interfering with the query structure, making it much harder for attackers to exploit SQL injection vulnerabilities."""
    )

    return

import pandas as pd  # Import pandas module

import sqlite3
import pandas as pd
import streamlit as st



def leaderboard_page():
    st.title("SQL Injection Leaderboard")

  

   
       
    c.execute("SELECT username, COUNT(*) AS scan_count FROM scans GROUP BY username ORDER BY scan_count DESC")
    scans_data = c.fetchall()

        # Fetch additional data from users and memberships tables
    leaderboard_data = []
    for username, scan_count in scans_data:
            c.execute("SELECT plan FROM memberships WHERE username=?", (username,))
            membership_result = c.fetchone()
            if membership_result:
                membership = membership_result[0]

                leaderboard_data.append({
                    'User': username,
                    'Scans': scan_count,
                    'Membership': membership
                })
            else:
                st.warning(f"No membership found for user: {username}")

        # Create a DataFrame from the fetched data
    df = pd.DataFrame(leaderboard_data)

        # Display the leaderboard table
    st.write(df)

    

    

def settings_page():
    st.title("Settings")
    
    st.header("User Settings")
    new_username = st.text_input("New Username", st.session_state.username)
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    
    if st.button("Update Credentials"):
        if new_username.strip() and new_password.strip() and new_password == confirm_password:
            success, message = update_credentials(st.session_state.username, new_username, new_password)
            if success:
                st.session_state.username = new_username
                st.success(message)
            else:
                st.error(message)
        else:
            st.error("Username or password cannot be empty, and passwords must match.")

    st.header("Notification Settings")
    notification_option = st.selectbox("Notification Frequency", ["Daily", "Weekly", "Monthly"])
    if st.button("Save Notification Settings"):
        st.success(f"Notification frequency set to {notification_option}.")

def history_page():
    st.title("Scan History")
    if hasattr(st.session_state, "username"):
        username = st.session_state.username
        c.execute("SELECT * FROM scans WHERE username=?", (username,))
        scans = c.fetchall()
        if scans:
            st.write("Scan History:")
            for scan in scans:
                # Ensure that the scan tuple has enough elements
                if len(scan) >= 4:
                    st.write(f"Scan Date: {scan[3]}, URL: {scan[2]}, Status: Completed")
                else:
                    st.error("Invalid scan data retrieved.")
        else:
            st.info("No scan history available.")
    else:
        st.error("You need to login to access the history page.")
        



if __name__ == "__main__":
    main()
