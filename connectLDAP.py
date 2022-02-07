from ldap3 import *
import os, json
from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta
import string
import random

app = Flask(__name__)



def generate_random_password():
    ## characters to generate password from
    alphabets_lower = list(string.ascii_lowercase)
    alphabets_upper = list(string.ascii_uppercase)
    digits = list(string.digits)
    special_characters = list("!@#$%^&*()")
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



# userNameLogon = ""
@app.route('/createuser', methods=['POST'])
def addUser():
    # Request data
    firstname = request.json['firstname']
    lastname = request.json['lastname']
    displayname = request.json['fullname']
    description = request.json['description']
    physicalDeliveryOfficeName = request.json['officename']
    telephoneNumber = request.json['tel']
    mail = request.json['mail']
    wWWHomePage = request.json['homepage']
    # userlogon = request.json['userlogon']
    # userpswd = request.json['userpwd']
    sub_dir = request.json['subOU'] # OU order: layer inner -> outer


    # Setup base connection
    domain = 'OPS-AD-TEST.ictc.ops'
    loginun = 'ICTC\Administrator'
    loginpw = 'vd8ntm9RQgDA'

    base_dn = 'OU=test,DC=ictc,DC=ops'

    # Set userdn
    userdn = 'CN='+displayname+','+base_dn
    if sub_dir == '':
        userdn = 'CN='+displayname+','+base_dn
    else:
        # userdn = 'CN='+displayname+',OU='+sub_dir+base_dn
        userdn = 'CN='+displayname+','+sub_dir+','+base_dn


    # connect - specifying port 636 is only for reference as it's inferred
    server = Server('ldaps://'+domain+':636')
    c = Connection(server, user=loginun, password=loginpw, authentication=NTLM)

    if not c.bind():
        exit(c.result)

    try:
        # userlogon = ""
        # if check_exist_user():
        #     userlogon = ""
        
        userlogon = check_exist_user(base_dn, c, firstname, lastname, 0)
        print("CHECK USERNAME RESULT = ", userlogon)

        # create user
        attribute = {
            'objectClass': ['organizationalPerson', 'person', 'top', 'user'],
            'givenname': firstname,
            'sn': lastname,
            'displayname': "{} {}".format(firstname, lastname),
            'description': description,
            'physicalDeliveryOfficeName': physicalDeliveryOfficeName,
            'telephoneNumber': telephoneNumber,
            'mail': mail,
            'wWWHomePage': wWWHomePage,
            'sAMAccountName': userlogon,
            'userPrincipalName': "{}@{}".format(userlogon, 'ictc.ops')
        }

        print(attribute)
        
        print("CHECK BF ADD")
        c.add(userdn, attributes=attribute)
        print("CHECK AF ADD")


        # Part: Set password, UAC and write log file
        if c.result['description']=='success':
            # set password - must be done before enabling user
            # you must connect with SSL to set the password
            userpswd = generate_random_password()

            c.extend.microsoft.modify_password(userdn, userpswd)
            
            searchParameters = { 'search_base': userdn, 
                'search_filter': '(objectClass=Person)',
                'attributes': ['cn', 'givenName','pwdLastSet'],
                'paged_size': 100 }
            c.search(**searchParameters)
            for entry in c.entries:
                # Check password already is set
                if str(entry['pwdLastSet']) != '1601-01-01 00:00:00+00:00':

                    # when password is set then enable user (after password set)
                    c.modify(userdn, {'userAccountControl': [('MODIFY_REPLACE', 512)]})


                    # Write log file before return success
                    try:
                        # Time zone in Thailand UTC+7
                        tz = timezone(timedelta(hours = 7))
                        # Create a date object with given timezone
                        date = datetime.now(tz=tz)
                        timeStamp = date.isoformat(sep = " ")
                        attribute['userpswd'] = userpswd
                        attribute['userdn'] = userdn
                        dateArr = str(timeStamp).split()
                        getDate = dateArr[0]

                        titleFiled = '//Fields: timeStamp#objectClass#givenname#sn#displayname#description#physicalDeliveryOfficeName#telephoneNumber#mail#wWWHomePage#sAMAccountName#userPrincipalName#userdn#userpswd'
                        with open("log/log_"+getDate+".txt", "a+", encoding="utf8") as file:
                            file.seek(0) # set position to start of file
                            lines = file.read().splitlines() # now we won't have those newlines
                            content = timeStamp+'#'+str(attribute['objectClass'])+'#'+str(attribute['givenname'])+'#'+str(attribute['sn'])+'#'+str(attribute['displayname'])+'#'+str(attribute['description'])+'#'+str(attribute['physicalDeliveryOfficeName'])+'#'+str(attribute['telephoneNumber'])+'#'+str(attribute['mail'])+'#'+str(attribute['wWWHomePage'])+'#'+str(attribute['sAMAccountName'])+'#'+str(attribute['userPrincipalName'])+'#'+str(attribute['userdn'])+'#'+str(attribute['userpswd'])+'\n'
                            if titleFiled in lines:
                                file.write(content)
                            else:
                                # write to file
                                file.write(titleFiled + "\n") # in append mode writes will always go to the end, so no need to seek() here
                                file.write(content)


                         # return response api case success
                        return jsonify({'result' : True,'errorMessage' : ''})

                    except Exception as err:
                        c.delete(userdn)
                        return jsonify({'result' : False, 'errorMessage' : 'Fail to write log file'})
                    
                else:
                    # paasword can not set so remove user that just add in AD and return response api case error
                    c.delete(userdn)
                    return jsonify({'result' : False,'errorMessage' : 'Fail to add user because condition set password not valid that cannot set password'})


        else:
            print(c.result)
            return jsonify({'result' : False, 'errorMessage' : c.result['description']})

    
    except Exception as e:
        # If the LDAP bind failed for reasons such as authentication failure.
        print('Fail to add user: ', e) 

    c.unbind()

def check_exist_user(dn, connection, firstname, lastname, index):
    print(index)
    usernamelogon = str(firstname+lastname[0:index+1]).lower()
    print(usernamelogon)
    elements = connection.search(dn,'(&(objectclass=user)(sAMAccountName='+usernamelogon+'))')
    # print("############################")
    # print(elements)
    if elements:
        print(elements)
        return check_exist_user(dn, connection, firstname, lastname, index+1)
    else:
        print(usernamelogon)
        return usernamelogon
        # userNameLogon = str(usernamelogon)
    # for element in elements:
    #     print(element)
        # if 'dn' in element:
        #     if element['dn'] != dn:
        #         if 'dn' in element:
        #             results.append(element['dn'])
        #             get_child_ou_dns(element['dn'], connection)


@app.route('/folderlist')
def getFolderList():
    allFolder = []

    path_to_json = 'data/'
    # Read json data in folder data
    for file_name in [file for file in os.listdir(path_to_json) if file.endswith('.json')]:
        currentFolder = []
        # Opening JSON file
        with open(path_to_json + file_name, encoding="utf8") as json_file:
            data = json.load(json_file)
            if data['data']:
                for i in data['data']:
                    i = [x for x in i if "_comment:" not in x] # filter comment from list
                    currentFolder = currentFolder+i # Concat list in 'data' key on current file json(concat in own file)

        allFolder = allFolder+currentFolder # Concat together list from each file(concat between file)


    return jsonify(allFolder)




                    

results = list()
@app.route('/getAllFolder')
def getAllFolder():
    all_ous = []

    # Setup base connection
    domain = 'OPS-AD-TEST.ictc.ops'
    loginun = 'ICTC\Administrator'
    loginpw = 'vd8ntm9RQgDA'

    base_dn = 'OU=test,DC=ictc,DC=ops'

    # connect - specifying port 636 is only for reference as it's inferred
    server = Server('ldaps://'+domain+':636')
    c = Connection(server, user=loginun, password=loginpw, authentication=NTLM)

    if not c.bind():
        exit(c.result)


    try:
        results.clear()
        get_child_ou_dns(base_dn, c)
        if results:
            for obj in results:
                current_ous = dict()
                getdn = str(obj).split(",OU=test,DC=ictc,DC=ops",1)[0]
                getCurrentFolder = str(obj).split(',')[0]

                current_ous['dn'] = getdn
                current_ous['name'] = str(getCurrentFolder).split("OU=",1)[1]
                all_ous.append(current_ous)
        
        return jsonify(all_ous)

    except Exception as e:
        print('Fail to get folder: ', e)


    c.unbind()
    
def get_child_ou_dns(dn, connection):
    elements = connection.extend.standard.paged_search(
        search_base=dn,
        search_filter='(objectCategory=organizationalUnit)',
        search_scope=LEVEL,
        paged_size=100)
    for element in elements:
        if 'dn' in element:
            if element['dn'] != dn:
                if 'dn' in element:
                    results.append(element['dn'])
                    get_child_ou_dns(element['dn'], connection)


if __name__ == '__main__':
    app.run(debug=True)



