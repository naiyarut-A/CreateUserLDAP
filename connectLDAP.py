from ldap3 import *
import os, json
from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta
import string
import random

import email #เรียกใช้งาน mudule email
import smtplib #เรียกใช้งาน module smtplib

from flask_mail import Mail, Message

app = Flask(__name__)
mail = Mail(app) # instantiate the mail class

# configuration of mail
app.config['MAIL_SERVER']='webmail.moc.go.th'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'naiyaruta@moc.go.th'
app.config['MAIL_PASSWORD'] = 'Na@11*07'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

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
        userdn = 'CN='+displayname+','+sub_dir+','+base_dn


    # connect - specifying port 636 is only for reference as it's inferred
    server = Server('ldaps://'+domain+':636')
    c = Connection(server, user=loginun, password=loginpw, authentication=NTLM)

    if not c.bind():
        exit(c.result)

    try:
        
        userlogon = check_exist_user(base_dn, c, firstname, lastname, 0)

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


                    send_data_to_email()
                    # send_email("mike@example.org", "output/python101.pdf")

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
    usernamelogon = str(firstname+lastname[0:index+1]).lower()
    elements = connection.search(dn,'(&(objectclass=user)(sAMAccountName='+usernamelogon+'))')

    if elements:
        return check_exist_user(dn, connection, firstname, lastname, index+1)
    else:
        return usernamelogon

# import os
# import smtplib

# from email import encoders
# from email.mime.text import MIMEText
# from email.mime.base import MIMEBase
# from email.mime.multipart import MIMEMultipart
# from email.utils import formatdate

# def send_email(email, pdf):
#     """
#     Send an email out
#     """
#     header0 = 'Content-Disposition'
#     header1 ='attachment; filename="%s"' % os.path.basename(pdf)
#     header = header0, header1
    
#     host = "webmail.moc.go.th"
#     server = smtplib.SMTP(host)
#     subject = "Test email from Python"
#     to = email
#     from_addr = "test@pylib.com"
#     body_text = "Here is the Alpha copy of Python 101, Part I"
    
#     # create the message
#     msg = MIMEMultipart()
#     msg["From"] = from_addr
#     msg["Subject"] = subject
#     msg["Date"] = formatdate(localtime=True)
#     msg["To"] = email
    
#     msg.attach( MIMEText(body_text) )
    
#     attachment = MIMEBase('application', "octet-stream")
#     try:
#         with open(pdf, "rb") as fh:
#             data = fh.read()
#         attachment.set_payload( data )
#         encoders.encode_base64(attachment)
#         attachment.add_header(*header)
#         msg.attach(attachment)
#     except IOError:
#         # msg = "Error opening attachment file %s" % file_to_attach
#         print(msg)
        
#     server.sendmail(from_addr, to, msg.as_string())

def send_data_to_email():
    msg = Message(
                'Hello',
                sender ='naiyaruta@moc.go.th',
                recipients = ['nat-naiyarat@hotmail.com']
               )
    msg.body = 'Hello Flask message sent from Flask-Mail'
    mail.send(msg)
    print("SEND MAIL SUCCESS")


#     print("CHECK DEBUG GET In FUNCTIOn")
#     # กำหนดตัวแปรชื่อผู้ใช้ และ รหัสผ่าน ตามบัญชีผู้ใช้
#     username = 'naiyaruta@moc.go.th'
#     password = 'Na@11*07'
#     # กำหนดตัวแปรอีเมลผู้ส่ง และ ผู้รับ
#     sender = 'naiyaruta@moc.go.th'
#     recipient = 'nat-naiyarat@hotmail.com'

#     # เนื้อหาของอีเมล
#     body = """
#     การส่งเมลล์ผ่าน SMTP ของ Mailgun ด้วย Python
#     """

#     mail = body

#     sender    = "naiyaruta@moc.go.th"
#     receivers = ["nat-naiyarat@hotmail.com"]


#     try:
#         headers = f"""From: {sender}
#         To: {", ".join(receivers)}
#         Subject: Hello
#         """

#         message = headers + "\n" + """
#         Hello
#         """

#         # ตั้งค่าเซิร์ฟเวอร์ด้วยชื่อโฮส และ พอร์ท
#         server = smtplib.SMTP('webmail.moc.go.th', 587)
#         #syntax ของ smtplib.SMTP( [host [, port [, local_hostname]]] )
#         server.login(username, password)
#         server.sendmail(sender, recipient, message)
#         server.quit()
#         print("Successfully sent email")

        
        
#     except Exception as e:
#         print ("Error: unable to send email")
    



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



