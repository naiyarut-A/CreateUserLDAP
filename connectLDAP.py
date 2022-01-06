from ldap3 import *
import os, json
from flask import Flask, request, jsonify

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
        c.add(userdn, attributes={
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
        })


        if c.result['description']=='success':
            # set password - must be done before enabling user
            # you must connect with SSL to set the password 
            c.extend.microsoft.modify_password(userdn, userpswd)

            # enable user (after password set)
            c.modify(userdn, {'userAccountControl': [('MODIFY_REPLACE', 512)]})
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

    # # Setup base connection
    # domain = 'OPS-AD-TEST.ictc.ops'
    # loginun = 'ICTC\Administrator'
    # loginpw = 'vd8ntm9RQgDA'

    # base_dn = 'OU=test,DC=ictc,DC=ops'

    # total_entries = 0

    # # connect - specifying port 636 is only for reference as it's inferred
    # server = Server('ldaps://OPS-AD-TEST.ictc.ops:636')
    # c = Connection(server, user=loginun, password=loginpw, authentication=NTLM)

    # if not c.bind():
    #     exit(c.result)


    # results = list()
    # elements = c.extend.standard.paged_search(
    #     search_base=base_dn,
    #     search_filter='(objectCategory=organizationalUnit)',
    #     search_scope=LEVEL,
    #     paged_size=100)

    # # total_entries += len(c.response)
    # # for entry in c.response:
    # #     print(entry)

    # # print('Total entries retrieved:', total_entries)

    # for element in elements:
    #     # print(element)
    #     # // Layer1: Outer
    #     if 'dn' in element:
    #         if element['dn'] != base_dn:
    #             if 'dn' in element:
    #                 # print(element['dn'])
    #                 subelements = c.extend.standard.paged_search(
    #                             search_base=element['dn'],
    #                             search_filter='(objectCategory=organizationalUnit)',
    #                             search_scope=LEVEL,
    #                             paged_size=100)
    #                 if subelements:
    #                     # // Layer2
    #                     resultsL2 = list()
    #                     headL2 = str(element['dn']).replace(','+base_dn,'')
    #                     print(headL2)
    #                     for subelement in subelements:
    #                         # print(subelement['dn'])
    #                         dnL2 = str(subelement['dn'])
    #                         subdnL2 = dnL2.replace(','+element['dn'],'')
    #                         resultsL2.append(subdnL2)
    #                     print(resultsL2) #key element'dn'L replace element'dn'L-1

    #                 else:
    #                     dn = str(element['dn'])
    #                     subOU = dn.replace(','+base_dn,'')
    #                     results.append(subOU)
    #                 # print(element['dn'])
    #                 # dn = str(element['dn'])
    #                 # subOU = dn.replace(','+base_dn,'')
    #                 # results.append(subOU)
    # # print(results)

    
    
    # # s = Server('172.30.1.197', port=636, use_ssl=True, get_info=ALL)
    # # admin_username = "Administrator@naanal.local"
    # # admin_password = "p@ssw0rd1"
    # # server = Server('ldaps://OPS-AD-TEST.ictc.ops:636')
    # # c = Connection(server, user=loginun, password=loginpw, authentication=NTLM)
    # # c.bind()
    # c.start_tls()

    # c.search(search_base = base_dn,
    #         search_filter = '(objectClass=OrganizationalUnit)',
    #         search_scope = SUBTREE,
    #         paged_size = 100)

    # total_entries += len(c.response)

    # for entry in c.response:
    #     print(entry)

    # print('Total entries retrieved:', total_entries)

    return jsonify(allFolder)
    # c.unbind()

if __name__ == '__main__':
    app.run(debug=True)



