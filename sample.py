from rssp import *
from pprint import pprint

# Create user
user = RsspConnector()
# log in
login = user.auth().login(
	username='TRUONGNNT_RP', password='12345678', relyingparty='TRUONGNNT_RP',
	profile='rssp-119.432-v2.0', user='thinhnt', usertype='USERNAME',
	userpassword='Thinhkrb@123', rememberme=True,
	signature='aCiPiDxEIfoWajqE+k4CCnf0pUcLi7NxgNGq5hQYC26RtD+oauzwYblL'
			  'U5oRTUM7YhLsfzXlCJ6VSgTFQze8vYw5x0ct4ReB5jP+1kb1RoCP+BT4r'
			  'jQYxWhsWlF5h6RhER24CzFLUx4hv4TssxuHNq9WtDcEIZww17qe8KkMGP'
			  'jTy7xQPkxJLIaf9c1ZPymrhfINa0wytDSSYY4NZH5YvuJfoAGZsRfuoyR'
			  'bwxxoDteVRl5eQ/QyJtrHNRVMYBEkg+ONzsS4KRX9dnmk0A1oJYPA63m6'
			  'ppXHsx3TZtxGieS0uYUyYfMTQlySo65TwlM7ZsH+hu5twqYv4kio3jPSpQ=='
)
# print(login.oauth2)
# pprint(login.detail)
# login = user1.auth().login(
# 	username='TRUONGNNT_RP', password='12345678', relyingparty='TRUONGNNT_RP',
# 	profile='rssp-119.432-v2.0',
# 	rememberme=True,
# 	signature='aCiPiDxEIfoWajqE+k4CCnf0pUcLi7NxgNGq5hQYC26RtD+oauzwYblL'
# 			  'U5oRTUM7YhLsfzXlCJ6VSgTFQze8vYw5x0ct4ReB5jP+1kb1RoCP+BT4r'
# 			  'jQYxWhsWlF5h6RhER24CzFLUx4hv4TssxuHNq9WtDcEIZww17qe8KkMGP'
# 			  'jTy7xQPkxJLIaf9c1ZPymrhfINa0wytDSSYY4NZH5YvuJfoAGZsRfuoyR'
# 			  'bwxxoDteVRl5eQ/QyJtrHNRVMYBEkg+ONzsS4KRX9dnmk0A1oJYPA63m6'
# 			  'ppXHsx3TZtxGieS0uYUyYfMTQlySo65TwlM7ZsH+hu5twqYv4kio3jPSpQ=='
# )

### revoke token
revoke = user.auth().revoke(
	profile='rssp-119.432-v2.0',
	tokentype=0
)
print(revoke.responseid)
### credential list
list = user1.credential().list(profile='rssp-119.432-v2.0')
# print(list.detail)

### info
# info = user1.credential().info(profile='rssp-119.432-v2.0')

### credential AUTHORIZE
# authorize = user1.credential().authorize(profile='rssp-119.432-v2.0', numsignatures=3, authorizecode='3t$uqUb[')

### credential EXTENDTRANSACTION
# extend = user1.credential().extendtransaction(profile='rssp-119.432-v2.0')

### SIGNHASH
sign = user.signature().signhash(profile='rssp-119.432-v2.0', message=['Hello World!'], operationmode='A')
# print(user1.responseid_signhash)

### SIGNPOLLING
polling = user.signature().signpolling(profile='rssp-119.432-v2.0', requestid=None)
# pprint(polling.detail)

### owner LIST
# ownerlist = user1.owner().list(profile='rssp-119.432-v2.0')

### owner RESET password
# step1 = user1.owner().resetpassword_step1(profile='rssp-119.432-v2.0', user='thinhnt')
# print(user1.responseid)
# step2 = user1.owner().resetpassword_step2(authorizecode="256826", profile='rssp-119.432-v2.0', user='thinhnt', requestid='TRUONGNNT_RP-201007095319-563605-913789', newpassword='Thinhkrb@123')





### credential change email
# changeemail = user1.credential().changeemail_step1(profile='rssp-119.432-v2.0', newemail='thanhthinhkrb@gmail.com')
# changeemail = user1.credential().changeemail_step2(profile='rssp-119.432-v2.0', otpoldemail='092801', otpnewemail='811081', requestid='TRUONGNNT_RP-201006170639-563537-319476')

### credential reset passphrase
# user1.credential().resetpassphrase_step1(profile='rssp-119.432-v2.0')
# print(user1.responseid)
# reset = user1.credential().resetpassphrase_step2(profile='rssp-119.432-v2.0', authorizecode="826380", requestid='TRUONGNNT_RP-201008150117-565084-025130')
# print(reset)

### owner change password
# change = user1.owner().changepassword(profile='rssp-119.432-v2.0', oldpassword="Thi@nhkrb123", newpassword="T@mic@8x")


### owner change email
# step1 = user1.owner().changeemail_step1(profile='rssp-119.432-v2.0', newemail='abcd@mail.com')
# step2 = user1.owner().changeemail_step2(profile='rssp-119.432-v2.0', requestid='HELLO-WORLD-201007101818-563644-039092', otpoldemail='981906', otpnewemail='461209')

### owner create
# user1.owner().create(username='alohadance', email='legolas.dizzy@yahoo.com.vn', phone='0947161746', identificationtype='PERSONAL-ID', identification='2415289876', profile='rssp-119.432-v2.0', fullname='Thinh Ngo', password='Thinhkrb@123')

### owner info
# info = user1.owner().info(profile='rssp-119.432-v2.0')

### owner change info
# changeinfo = user1.owner().changeinfo(profile='rssp-119.432-v2.0')

### owner sendotp
# sendotp = user1.owner().sendotp(profile='rssp-119.432-v2.0', user='alohadance', usertype='USERNAME')
# print(user1.responseid)

### agreements create
# create = user1.agreements().create(profile='rssp-119.432-v2.0', agreementuuid='thanhthinhkrb1234')
# print(create)

## agreements assign
# assign = user1.agreements().assign(profile='rssp-119.432-v2.0', agreementuuid='thanhthinhkrb1234', user='alohadance', usertype='USERNAME', authorizecode='758862', requestid='TRUONGNNT_RP-201007150110-563790-262813')

### owner logging
# logging = user1.owner().logging(profile='rssp-119.432-v2.0')

### queries/owner/history
# ownerhistory = user1.queries().owner_history(profile='rssp-119.432-v2.0', actions=['ALL', 'CHANGE_PASSWORD'])
# pprint(ownerhistory)
#
### queries/credential/history
# credentialhistory = user1.queries().credential_history(profile='rssp-119.432-v2.0')

### get system/getcertificateauthorities
# get = user1.system().getcertificateauthorities(profile='rssp-119.432-v2.0')
# pprint(get)

### get signingprofile
# get = user1.system().getcertificateprofiles(profile='rssp-119.432-v2.0', caname='TrustCA G1')
# pprint(get)

### credential issue
# issue = user1.credential().issue(certificateprofile='T2OSB21Y', profile='rssp-119.432-v2.0', authmode='EXPLICIT/PIN', commonname='Company Name', organization='Organization', stateorprovince='20', country='VN', title='ABcD', identype_value={'PERSONAL-ID': '123871237', 'TAX-CODE': '0.9.2342.19200300.100.1.1'})
# print(issue)

### signing profile
# signingprofile = user1.system().getcountries(profile='rssp-119.432-v2.0')
# pprint(signingprofile)