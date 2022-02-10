import string
import random


def generate_random_password():
    ## characters to generate password from
    alphabets_lower = list(string.ascii_lowercase)
    alphabets_upper = list(string.ascii_uppercase)
    digits = list(string.digits)
    special_characters = list("!@&*")
    # characters = list(string.ascii_uppercase + string.digits + string.ascii_lowercase + "!@&*")


    ## length of password from the user
    alphabets_count = 3
    digits_count = 3
    special_characters_count = 2


    # ## shuffling the characters
    # random.shuffle(characters)
    
    ## picking random characters from the list
    password = []
    ## picking random alphabets upper
    for _ in range(alphabets_count):
        password.append(random.choice(alphabets_upper))

    ## picking random alphabets lower
    for _ in range(alphabets_count):
        password.append(random.choice(alphabets_lower))

    for _ in range(digits_count):
        password.append(random.choice(digits))

    ## picking random alphabets
    for _ in range(special_characters_count):
        password.append(random.choice(special_characters))

    ## shuffling the resultant password
    # random.shuffle(password)

    ## converting the list to string
    return "".join(password)


def check_exist_user(dn, connection, firstname, lastname, index):
    usernamelogon = str(firstname+lastname[0:index+1]).lower()
    elements = connection.search(dn,'(&(objectclass=user)(sAMAccountName='+usernamelogon+'))')

    if elements:
        return check_exist_user(dn, connection, firstname, lastname, index+1)
    else:
        return usernamelogon