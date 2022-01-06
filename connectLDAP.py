from ldap3 import *
import os, json
from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta

app = Flask(__name__)

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
    userlogon = request.json['userlogon']
    userpswd = request.json['userpwd']
    sub_dir = request.json['subOU'] # OU order: layer inner -> outer


    # Setup base connection
    domain = 'OPS-AD-TEST.ictc.ops'
    loginun = 'ICTC\Administrator'
    loginpw = 'vd8ntm9RQgDA'

    base_dn = ',OU=test,DC=ictc,DC=ops'

    # Set userdn
    userdn = 'CN='+displayname+base_dn
    if sub_dir == '':
        userdn = 'CN='+displayname+base_dn
    else:
        # userdn = 'CN='+displayname+',OU='+sub_dir+base_dn
        userdn = 'CN='+displayname+','+sub_dir+base_dn


    # connect - specifying port 636 is only for reference as it's inferred
    server = Server('ldaps://'+domain+':636')
    c = Connection(server, user=loginun, password=loginpw, authentication=NTLM)

    if not c.bind():
        exit(c.result)

    try:
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
        
        c.add(userdn, attributes=attribute)


        if c.result['description']=='success':
            # set password - must be done before enabling user
            # you must connect with SSL to set the password 
            c.extend.microsoft.modify_password(userdn, userpswd)
            # enable user (after password set)
            c.modify(userdn, {'userAccountControl': [('MODIFY_REPLACE', 512)]})

            # Write log file before return success
            try:
                # Time zone in Thailand UTC+7
                tz = timezone(timedelta(hours = 7))
                # Create a date object with given timezone
                date = datetime.now(tz=tz)
                timeStamp = date.isoformat(sep = " ")
                print("current time:-", date.isoformat(sep = " "))

                attribute['userpswd'] = userpswd
                attribute['userdn'] = userdn

                
                log = open("log.txt", "a")
                content = 'timeStamp: '+timeStamp+'  '+'valueObject: '+str(attribute)+'\n'
                log.write(content)
                log.close()
            except Exception as err:
                return jsonify({'result' : False, 'errorMessage' : 'Fail to write log file: \n'+err})
            

            return jsonify({'result' : True,'errorMessage' : ''})

        else:
            print(c.result)
            return jsonify({'result' : False, 'errorMessage' : c.result['description']})

    
    except Exception as e:
        # If the LDAP bind failed for reasons such as authentication failure.
        print('Fail to add user: ', e) 

    c.unbind()


@app.route('/folderlist')
def getFolderList():
    allFolder = []

    path_to_json = 'data/'
    # Read json data in folder data
    for file_name in [file for file in os.listdir(path_to_json) if file.endswith('.json')]:
        currentFolder = []
        # Opening JSON file
        with open(path_to_json + file_name) as json_file:
            data = json.load(json_file)
            if data['data']:
                for i in data['data']:
                    i = [x for x in i if "_comment:" not in x] # filter comment from list
                    currentFolder = currentFolder+i # Concat list in 'data' key on current file json(concat in own file)

        allFolder = allFolder+currentFolder # Concat together list from each file(concat between file)


    return jsonify(allFolder)
    # c.unbind()

if __name__ == '__main__':
    app.run(debug=True)



