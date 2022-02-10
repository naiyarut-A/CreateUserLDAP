from ldap3 import *
import os, json
from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta

from flask_mail import Mail, Message

from businessLogic import generate_random_password, check_exist_user

app = Flask(__name__)

# configuration of mail
app.config['MAIL_SERVER']='webmail.moc.go.th'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'naiyaruta@moc.go.th'
app.config['MAIL_PASSWORD'] = 'Na@11*07'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


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
        userdn = 'CN='+displayname+','+sub_dir+','+base_dn


    # connect - specifying port 636 is only for reference as it's inferred
    server = Server('ldaps://'+domain+':636')
    c = Connection(server, user=loginun, password=loginpw, authentication=NTLM)

    if not c.bind():
        exit(c.result)

    userlogon = check_exist_user(base_dn, c, firstname, lastname, 0)
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

    try:
        # create user
        c.add(userdn, attributes=attribute)

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

                        send_data_to_email(attribute)
                         # return response api case success
                        return jsonify({'result' : True,'errorMessage' : ''})
                    except Exception as err:
                        c.delete(userdn)
                        # send_data_to_email(attribute, False)
                        send_result_fail_to_email(firstname, 
                                                lastname, 
                                                displayname, 
                                                description, 
                                                physicalDeliveryOfficeName, 
                                                telephoneNumber, mail,
                                                wWWHomePage, sub_dir)
                        return jsonify({'result' : False, 'errorMessage' : 'Fail to write log file'})
                    
                else:
                    # paasword can not set so remove user that just add in AD and return response api case error
                    c.delete(userdn)
                    # send_data_to_email(attribute, False)
                    print("CHECK DEBUG 1")
                    send_result_fail_to_email(firstname, 
                                            lastname, 
                                            displayname, 
                                            description, 
                                            physicalDeliveryOfficeName, 
                                            telephoneNumber, mail,
                                            wWWHomePage, sub_dir)
                    return jsonify({'result' : False,'errorMessage' : 'Fail to add user because condition set password not valid that cannot set password'})

        else:
            send_result_fail_to_email(firstname, 
                                    lastname, 
                                    displayname, 
                                    description, 
                                    physicalDeliveryOfficeName, 
                                    telephoneNumber, mail,
                                    wWWHomePage, sub_dir)
            return jsonify({'result' : False, 'errorMessage' : c.result['description']})

    
    except Exception as e:
        # If the LDAP bind failed for reasons such as authentication failure.
        print('Fail to add user: ', e)
        send_result_fail_to_email(firstname, 
                                lastname, 
                                displayname, 
                                description, 
                                physicalDeliveryOfficeName, 
                                telephoneNumber, mail,
                                wWWHomePage, sub_dir)
        return jsonify({'result' : False, 'errorMessage' : e})
    
    
    c.unbind()
    


def send_data_to_email(data):
    msg_success = Message(
                'แจ้งชื่อผู้ใช้งานและรหัสผ่าน',
                sender ='naiyaruta@moc.go.th',
                recipients = ['nat-naiyarat@hotmail.com','naiyaruta@moc.go.th']
               )
    with app.open_resource("log/log_2022-02-08.txt") as fp:  
        msg_success.attach("log_2022-02-08.txt","text/plain",fp.read())
    
    msg_success.html = """<h2>แจ้งชื่อผู้ใช้งานและรหัสผ่าน</h2>\n
                    <p>&nbspตามที่ท่านมีความประสงค์ใช้งานระบบสารสนเทศ สำนักงานปลัดกระทรวงพาณิชย์นั้น<br> 
                    บัดนี้ได้ดำเนินการเรียบร้อยแล้วตามเอกสารแนบ<br> หากพบปัญหาหรือต้องการสอบถามเพิ่มเติม &nbsp ติดต่อ ...  โดยใช้ชื่อผู้ใช้งานและรหัสผ่านตามด้านล่าง</p>
                    <p>ชื่อ-สกุล: """+str(data['displayname'])+"""<br>
                    ชื่อผู้ใช้งาน: """+str(data['sAMAccountName'])+"""<br>
                    รหัสผ่าน: """+str(data['userpswd'])+"""<br>
                    e-mail account: """+str(data['userPrincipalName'])+"""</p>"""
    mail.send(msg_success)


def send_result_fail_to_email(firstname, lastname, displayname, description, officeName, tel, email, homepage, subDir):
    msg = Message(
                'Fail to add user',
                sender ='naiyaruta@moc.go.th',
                recipients = ['nat-naiyarat@hotmail.com']
               )
    msg.html = """<h2>เพิ่ม user ไม่สำเร็จ</h2>\n
                    <p>firstname: """+firstname+"""<br>
                    lastname: """+lastname+"""<br>
                    displayname: """+displayname+"""<br>
                    description: """+description+"""<br>
                    physicalDeliveryOfficeName: """+officeName+"""<br>
                    telephoneNumber: """+tel+"""<br>
                    email: """+email+"""<br>
                    wWWHomePage: """+homepage+"""<br>
                    subDir: """+subDir+"""</p>"""
    mail.send(msg)




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



