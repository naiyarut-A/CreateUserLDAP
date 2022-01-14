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


        # Part: Set password, UAC and write log file
        if c.result['description']=='success':
            # set password - must be done before enabling user
            # you must connect with SSL to set the password 
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
    # c.unbind()

results = list()
def get_child_ou_dns(dn, connection):
    elements = connection.extend.standard.paged_search(
        search_base=dn,
        search_filter='(objectCategory=organizationalUnit)',
        search_scope=LEVEL,
        paged_size=100)
    for element in elements:
        # print("CHECK ELEMENT: ", element)
        if 'dn' in element:
            if element['dn'] != dn:
                if 'dn' in element:
                    results.append(element['dn'])
                    get_child_ou_dns(element['dn'], connection)
                    # print("CHECK REULT: ", results)
                    
    # return(results)


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


    # print(get_child_ou_dns(base_dn,c))
    # try:
    #     get_child_ou_dns(base_dn, c)
    #     convertToArr = np.array(results)
    #     return jsonify(convertToArr)


    # except Exception as e:
    #     # If the LDAP bind failed for reasons such as authentication failure.
    #     print('Fail to get folder: ', e) 

    # c.unbind()
    try:
        get_child_ou_dns(base_dn, c)
        if results:
            for obj in results:
                current_ous = dict()
                ouArr = str(obj).split(',')
                getdn = str(obj).split(",OU=test,DC=ictc,DC=ops",1)[0]
                getCurrentFolder = ouArr[0]

                # for i in (len(ouArr)-3):
                #     getdn = ouArr[i]+','
                # print(getdn)

                current_ous['dn'] = getdn
                current_ous['name'] = str(getCurrentFolder)
                all_ous.append(current_ous)
        
        return jsonify(all_ous)

    except Exception as e:
        print('Fail to get folder: ', e)
        # return jsonify({'Fail to get folder'}) 

    c.unbind()
    
    
    # my_json_string = json.dumps({'results': results})
    # convertToArr = np.array(results)
    

    # all_ous = get_child_ou_dns(base_dn,c)
    # print("GET TOTAL RESULT -> ",results)
    # return jsonify(all_ous)

    # ou_dn_process_status['OU=test,DC=ictc,DC=ops'] = {'need_to_process':True}
    # has_searches_to_process = True
    # while has_searches_to_process:
    #     ou_dn_process_status_keys = list(ou_dn_process_status.keys())
    #     for dn in ou_dn_process_status_keys:
    #         if ou_dn_process_status[dn]['need_to_process']:
    #             all_ous[dn] = get_child_ou_dns(base_dn, c)

    #             print(all_ous[dn])

    #             ou_dn_process_status[dn]['need_to_process'] = False
    #             for child_ou_dn in all_ous[dn]:
    #                 if not child_ou_dn in ou_dn_process_status:
    #                     ou_dn_process_status[child_ou_dn] = {'need_to_process':True}
    #     has_searches_to_process = False
    #     for dn in ou_dn_process_status:
    #         if ou_dn_process_status[dn]['need_to_process']:
    #             has_searches_to_process = True
    # return all_ous

if __name__ == '__main__':
    app.run(debug=True)



