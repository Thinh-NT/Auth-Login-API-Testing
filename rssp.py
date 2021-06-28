import json
import hashlib

import requests

from base import *
import rssperrors


class RsspConnector:
	access_token = None
	refresh_token = None
	logged_in = False
	bs = None
	credentialid = None
	SAD = None
	responseid = None
	responseid_signhash = None

	def auth(self):
		return self.Auth(self)

	def credential(self):
		return self.Credential(self)

	def owner(self):
		return self.Owner(self)

	def signature(self):
		return self.Signatures(self)

	def agreements(self):
		return self.Agreements(self)

	def queries(self):
		return self.Queries(self)

	def system(self):
		return self.System(self)

	class Auth:
		def __init__(self, user):
			self.user = user

		def gettwofactormethod(self, username, password, signature, relyingparty, profile, user='', usertype=None):
			pkcssignature = BaseInfo.pkcssignature(username, password, signature)
			ssl = BaseInfo.ssl(username, password, signature, pkcssignature)

			headers = {
				'authorization': f'SSL2 {ssl}',
				'Content-Type': 'application/json'
			}
			payload = {
				'profile': f'{profile}',
				'relyingParty': f'{relyingparty}',
				'user': f'{user}',
				'userType': f'{usertype}'
			}
			payload = json.dumps(payload)
			response = requests.request(
				'POST', url + 'auth/getTwoFactorMethod',
				headers=headers, data=payload, timeout=10
			)
			info = response.json()
			codeerror = response.json().get('error')
			if codeerror == 0:
				self.user.responseid_lastcall = info.get('responseID')
				two_factor_method = info.get('twoFactorMethod')
				self.user.twofactormethod = two_factor_method
				return two_factor_method
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def login(
				self, username, password, signature, relyingparty, profile, user='',
				usertype=None, rememberme=False, rprequestid=None, requestid=None, userpassword=None,
				iccid=None, imei=None, macaddr=None, lang=None, notificationmessage=None,
				messagecaption=None, message=None, logouri=None, bgimageuri=None, rpicouri=None, rpname=None,
				vcenabled=None, refresh_token=None,
				scaidentity=None, confirmationpolicy=None, validityperiod=None, hashes=None, hashalgorithmoid=None
		):

			pkcssignature = BaseInfo.pkcssignature(username, password, signature)
			if user != '' and usertype:
				basic = base64.b64encode(bytes(f'{usertype}:{user}:{userpassword}', 'utf-8')).decode('utf-8')

			else:
				basic = None

			self.user.bs = basic

			ssl = BaseInfo.ssl(username, password, signature, pkcssignature)

			if not basic:
				headers = {
					'authorization': f'SSL2 {ssl}',
					'Content-Type': 'application/json'
				}
			else:
				headers = {
					'authorization': f'SSL2 {ssl}, basic {basic}',
					'Content-Type': 'application/json'
				}
			if refresh_token:
				headers = {
					'Authorization': f'Bearer {refresh_token}',
					'Content-Type': 'application/json'
				}
			if user and usertype:
				if self.gettwofactormethod(
						username, password, signature, relyingparty, profile, user,
						usertype
				) == 'TSE' and not notificationmessage:
					raise rssperrors.MissingInfomation
				else:
					pass

			else:
				pass

			payload = {
				'relyingParty': relyingparty,
				'profile': profile,
				'rememberMe': rememberme,
				'rpRequestID': rprequestid,
				'requestID': requestid,
				'clientInfo': {
					'iccid': iccid,
					'imei': imei,
					'macAddr': macaddr
				},
				'lang': lang,
				'tseNotification': {
					'notificationMessage': notificationmessage,
					'messageCaption': messagecaption,
					'message': message,
					'logoURI': logouri,
					'bgImageURI': bgimageuri,
					'rpIconURI': rpicouri,
					'rpName': rpname,
					'vcEnabled': vcenabled,
					'scaIdentity': scaidentity,
					'confirmationPolicy': confirmationpolicy,
					'validityPeriod': validityperiod,
					'hashes': hashes,
					'hashAlgorithmOID': hashalgorithmoid
				}
			}
			payload = json.dumps(payload)

			response = requests.request(
				'POST', url + 'auth/login', headers=headers,
				data=payload
			)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				self.user.access_token, self.user.refresh_token = [
															info.get('accessToken'),
															info.get('refreshToken')
														]
				self.user.logged_in = True

				class MyLogin:
					access_token, refresh_token = [
							info.get('accessToken'),
							info.get('refreshToken')
						]
					responseid = info.get('responseID')
					if info.get('ownerInfo'):
						email = info.get('ownerInfo').get('email')
						fullname = info.get('ownerInfo').get('fullName')
						phone = info.get('ownerInfo').get('phone')
						oauth2 = info.get('ownerInfo').get('oauth2')
					authorizecode = info.get('authorizeToken')

					def __str__(self):
						return str(info)
				return MyLogin()
			else:
				raise Exception(f"Error code {info.get('error')} : {info.get('errorDescription')}")

		def revoke(
				self, tokentype=0, access_token=None, refresh_token=None, rprequestid=None, requestid=None,
				lang="", agreementuuid=None, credentialid=None, profile=None
		):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound("Please log in first.")
				else:
					pass

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}

			if tokentype == 1:
				payload = {
					'tokenType': 1,
					'rpRequestID': rprequestid,
					'requestID': requestid,
					'token': refresh_token,
					'lang': lang,
					'agreementUUID': agreementuuid,
					'credentialID': credentialid,
					'profile': profile
				}

			elif tokentype == 0:
				payload = {
					'tokenType': 0,
					'rpRequestID': rprequestid,
					'requestID': requestid,
					'token': access_token,
					'lang': lang,
					'agreementUUID': agreementuuid,
					'credentialID': credentialid,
					'profile': profile
				}
			else:
				raise rssperrors.OptionError

			payload = json.dumps(payload)

			response = requests.request(
				'POST', url + 'auth/revoke',
				headers=headers,
				data=payload
			)
			try:
				info = response.json()
				if info.get('error') == 0:
					self.user.responseid_lastcall = info.get('responseID')

					class MyRevoke:
						responseid = info.get('responseID')

						def __str__(self):
							return str(info)
					return MyRevoke()
				else:
					raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")
			except Exception:
				raise ConnectionError()

	class Credential:

		def __init__(self, user):
			self.user = user

		def list(
				self, profile, access_token=None, rprequestid=None, requestid=None,
				agreementuuid=None, certificatestatus='ALL', certificatepurpose='ALL',
				certinfo=None, certificates=None, authinfo=None, lang=''
		):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			else:
				pass

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}

			payload = {
				"profile": profile,
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"agreementUUID": agreementuuid,
				"searchConditions": {
					"certificateStatus": certificatestatus,
					"certificatePurpose": certificatepurpose
				},
				"certInfo": certinfo,
				"certificates": certificates,
				"authInfo": authinfo,
				"lang": lang
			}
			payload = json.dumps(payload)

			response = requests.request(
				"POST", url + "credentials/list",
				headers=headers, data=payload
			)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError

			if info.get('error') == 0:
				self.user.credentialid = info.get("certs")[0].get("credentialID")
				self.user.responseid_lastcall = info.get('responseID')

				class MyList:
					cert_issuerdn = info.get("certs")[0].get("issuerDN")
					cert_serialnumber = info.get("certs")[0].get("serialNumber")
					cert_credentialid = info.get("certs")[0].get("credentialID")
					cert_subjectdn = info.get("certs")[0].get("subjectDN")
					cert_validfrom = info.get("certs")[0].get("validFrom")
					cert_validto = info.get("certs")[0].get("validTo")
					cert_profilename = None
					cert_profiledescription = None
					if info.get("certs")[0].get("certificateProfile"):
						cert_profilename = info.get("certs")[0].get("name")
						cert_profiledescription = info.get("certs")[0].get("description")
					cert_purpose = info.get("certs")[0].get("purpose")
					cert_multisign = info.get("certs")[0].get("multisign")
					cert_remaining_signing_counter = info.get("certs")[0].get("remainingSigningCounter")
					cert_version = info.get("certs")[0].get("version")
					cert_certificates = info.get("certs")[0].get("certificates")
					cert_authorizationemail = info.get("certs")[0].get("authorizationEmail")
					cert_authorizationphone = info.get("certs")[0].get("authorizationPhone")
					cert_status = info.get("certs")[0].get("status")

					def __str__(self):
						return str(info)
				return MyList()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def info(
				self, profile, access_token=None,
				rprequestid=None, requestid=None,
				lang='', agreementuuid=None,
				credentialid=None, certificates='single',
				certinfo=False, authinfo=False):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				'rpRequestID': rprequestid,
				'requestID': requestid,
				'lang': lang,
				'agreementUUID': agreementuuid,
				'credentialID': credentialid,
				'certificates': certificates,
				'certInfo': certinfo,
				'authInfo': authinfo,
				'profile': profile
			}
			payload = json.dumps(payload)
			response = requests.request(
				'POST', url + 'credentials/info',
				headers=headers, data=payload
			)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyInfo:
					cert_status = info.get('cert').get('status')
					cert_certificates = info.get('cert').get('certificates')
					cert_issuerdn = info.get('cert').get('issuerDN')
					cert_serialnumber = info.get('cert').get('serialNumber')
					cert_thumbprint = info.get('cert').get('thumbprint')
					cert_subjectdn = info.get('cert').get('subjectDN')
					cert_validfrom = info.get('cert').get('validFrom')
					cert_validto = info.get('cert').get('validTo')
					cert_certificateprofile_name = None
					cert_certificateprofile_description = None
					if info.get('cert').get('certificateProfile'):
						cert_certificateprofile_name = info.get('cert').get('certificateProfile').get('name')
						cert_certificateprofile_description = info.get('cert').get('certificateProfile').get('description')
					cert_purpose = info.get('cert').get('purpose')
					cert_version = info.get('cert').get('version')
					sharedmode = info.get('sharedMode')
					createdrp = info.get('createdRP')
					multisign = info.get('multisign')
					authmodes = info.get('authModes')
					authmode = info.get('authMode')
					scal = info.get('SCAL')
					contractexpirationdate = info.get('contractExpirationDate')
					remainingsigningcounter = info.get('remainingSigningCounter')
					authorization_email = info.get('authorizationEmail')
					authorization_phone = info.get('authorizationPhone')
					defaultpassphraseenabled = info.get('defaultPassphraseEnabled')

					def __str__(self):
						return str(info)
				return MyInfo()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def sendotp(
				self, profile, access_token=None, rprequestid=None, requestid=None,
				agreementuuid=None, credentialid=None,
				notificationtemplate=None, notificationsubject=None, lang='',
		):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			else:
				pass

			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"agreementUUID": agreementuuid,
				"credentialID": credentialid,
				"notificationTemplate": notificationtemplate,
				"notificationSubject": notificationsubject,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request(
				"POST", url + "credentials/sendOTP",
				headers=headers, data=payload
			)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError

			if info.get('error') == 0:
				return response
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def authorize(
				self, profile, access_token=None, rprequestid=None,
				requestid=None, agreementuuid=None, credentialid=None,
				authorizecode=None, lang='', numsignatures=None, hashes=None,
				hashalgorithmoid=None, iccid=None,
				imei=None, macaddr=None, instanceuuid=None, notificationmessage=None,
				messagecaption=None, message=None, logouri=None, bgimageuri=None,
				rpicouri=None, rpname=None, confirmationpolicy='PIN', vcenabled=True,
				acenabled=False, operationmode=None, scaidentity=None,
				responseuri=None, validityperiod=None, documents=None,
				signalgo=None, signalgoparams=None
		):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			else:
				pass

			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound

			if self.user.bs is None and agreementuuid is None:
				raise Exception('Need login with username or agreementuuid')
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"agreementUUID": agreementuuid,
				"credentialID": credentialid,
				"authorizeCode": authorizecode,
				"lang": lang,
				"numSignatures": numsignatures,
				"documentDigests": {
					"hashes": hashes,
					"hashAlgorithmOID": hashalgorithmoid
				},
				"clientInfo": {
					"iccid": iccid,
					"imei": imei,
					"macAddr": macaddr,
					"instanceUUID": instanceuuid
				},
				"notificationMessage": notificationmessage,
				"messageCaption": messagecaption,
				"message": message,
				"logoURI": logouri,
				"bgImageURI": bgimageuri,
				"rpIconURI": rpicouri,
				"rpName": rpname,
				"confirmationPolicy": confirmationpolicy,
				"vcEnabled": vcenabled,
				"acEnabled": acenabled,
				"operationMode": operationmode,
				"scaIdentity": scaidentity,
				"responseURI": responseuri,
				"validityPeriod": validityperiod,
				"profile": profile,
				"documents": documents,
				"signAlgo": signalgo,
				"signAlgoParams": signalgoparams
			}
			payload = json.dumps(payload)
			response = requests.request(
				"POST", url + "credentials/authorize",
				headers=headers, data=payload
			)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				self.user.SAD = info.get("SAD")

				class MyAuthorize:
					responseid = info.get('responseID')
					sad = info.get('SAD')
					expiresin = info.get('expiresIn')
					remainingcounter = info.get('remainingCounter')
					templockoutduration = info.get('tempLockoutDuration')
					if info.get('documentDigests'):
						hashes = info.get('respdocumentDigestsonseID').get('hashes')
						hashalgorithmoid = info.get('respdocumentDigestsonseID').get('hashAlgorithmOID')

					def __str__(self):
						return str(info)
				return MyAuthorize()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def extendtransaction(
				self, profile, access_token=None, rprequestid=None,
				requestid=None, agreementuuid=None,
				credentialid=None,
				SAD=None, lang='', hashes=None, hashalgorithmoid=None,
				iccid=None, imei=None, macaddr=None, instanceuuid=None,
				notificationmessage=None, messagecaption=None, message=None,
				logouri=None, bgimageuri=None, rpicouri=None, rpname=None, confirmationpolicy='PIN',
				vcenabled=True, acenabled=False, operationmode='S', scaidentity=None, responseuri=None,
				validityperiod=None, documents=None, signalgo=None, signalgoparams=None
		):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			else:
				pass

			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound

			if SAD is None:
				SAD = self.user.SAD
				if SAD is None:
					raise rssperrors.SADNotFound

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"agreementUUID": agreementuuid,
				"credentialID": credentialid,
				"SAD": SAD,
				"lang": lang,
				"documentDigests": {
					"hashes": hashes,
					"hashAlgorithmOID": hashalgorithmoid
				},
				"clientInfo": {
					"iccid": iccid,
					"imei": imei,
					"macAddr": macaddr,
					"instanceUUID": instanceuuid
				},
				"notificationMessage": notificationmessage,
				"messageCaption": messagecaption,
				"message": message,
				"logoURI": logouri,
				"bgImageURI": bgimageuri,
				"rpIconURI": rpicouri,
				"rpName": rpname,
				"confirmationPolicy": confirmationpolicy,
				"vcEnabled": vcenabled,
				"acEnabled": acenabled,
				"operationMode": operationmode,
				"scaIdentity": scaidentity,
				"responseURI": responseuri,
				"validityPeriod": validityperiod,
				"profile": profile,
				"documents": documents,
				"signAlgo": signalgo,
				"signAlgoParams": signalgoparams
			}
			payload = json.dumps(payload)
			response = requests.request(
				"POST", url + "credentials/extendTransaction",
				headers=headers, data=payload
			)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				self.user.SAD = info.get("SAD")

				class MyExtend:
					sad = info.get('SAD')
					expiresin = info.get('expiresIn')
					responseid = info.get('responseID')

					def __str__(self):
						return str(info)
				return MyExtend()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def changepassphrase(
					self, profile, oldpassphrase, newpassphrase,
					access_token=None, rprequestid=None, requestid=None,
					credentialid=None, agreementuuid=None, lang=None
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if self.user.bs is None and agreementuuid is None:
				raise Exception('agreementUUID is required.')

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"credentialID": credentialid,
				"agreementUUID": agreementuuid,
				"oldPassphrase": oldpassphrase,
				"newPassphrase": newpassphrase,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request(
				"POST", url + "credentials/changePassphrase",
				headers=headers, data=payload
			)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					remainingcounter = info.get('remainingCounter')
					tempLockoutduration = info.get('tempLockoutDuration')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def resetpassphrase_step1(
				self, profile, access_token=None, credentialid=None, rprequestid=None,
				requestid=None, agreementuuid=None,
				notificationtemplate=None, notificationsubject=None, lang=''
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if self.user.bs is None and agreementuuid is None:
				raise Exception('agreementUUID is required.')

			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			# Step 1
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"requestType": "request",
				"credentialID": credentialid,
				"agreementUUID": agreementuuid,
				"notificationTemplate": notificationtemplate,
				"notificationSubject": notificationsubject,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request(
				"POST", url + "credentials/resetPassphrase",
				headers=headers, data=payload
			)
			# return response
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				self.user.responseid = info.get('responseID')

				class MyClass:
					responseid = info.get('responseID')
					templockoutduration = info.get('tempLockoutDuration')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def resetpassphrase_step2(
				self, profile, authorizecode, access_token=None, credentialid=None, rprequestid=None,
				agreementuuid=None, newpassphrase=None, requestid=None,
				notificationtemplate=None, notificationsubject=None, lang=''
		):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if self.user.bs is None and agreementuuid is None:
				raise Exception('agreementUUID is required.')

			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound

			if requestid is None:
				requestid = self.user.responseid
				if requestid is None:
					raise Exception("Must do step 1.")

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			# Step 2
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"requestType": "confirm",
				"credentialID": credentialid,
				"agreementUUID": agreementuuid,
				"authorizeCode": authorizecode,
				"newPassphrase": newpassphrase,
				"notificationTemplate": notificationtemplate,
				"notificationSubject": notificationsubject,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request(
				"POST", url + "credentials/resetPassphrase",
				headers=headers, data=payload
			)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					templockoutduration = info.get('tempLockoutDuration')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def changeemail_step1(
				self, profile, newemail,
				access_token=None, credentialid=None,
				agreementuuid=None, rprequestid=None, requestid=None,
				notificationtemplate=None, notificationsubject=None, lang=''
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if self.user.bs is None and agreementuuid is None:
				raise Exception('agreementUUID is required.')

			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			# Step 1
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"requestType": "request",
				"credentialID": credentialid,
				"agreementUUID": agreementuuid,
				"newEmail": newemail,
				"notificationTemplate": notificationtemplate,
				"notificationSubject": notificationsubject,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request(
				"POST", url + "credentials/changeEmail",
				headers=headers, data=payload
			)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				self.user.responseid = info.get('responseID')

				class MyClass:
					responseid = info.get('responseID')
					templockoutduration = info.get('tempLockoutDuration')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def changeemail_step2(
				self, profile, otpoldemail, otpnewemail,
				access_token=None, rprequestid=None,
				requestid=None, credentialid=None, agreementuuid=None, lang=''
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if self.user.bs is None and agreementuuid is None:
				raise Exception('agreementUUID is required.')

			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			# Step 2
			if requestid is None:
				requestid = self.user.responseid
				if requestid is None:
					raise Exception("Must do step 1.")

			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"requestType": "confirm",
				"credentialID": credentialid,
				"agreementUUID": agreementuuid,
				"otpOldEmail": otpoldemail,
				"otpNewEmail": otpnewemail,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request(
				"POST", url + "credentials/changeEmail",
				headers=headers, data=payload
			)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					templockoutduration = info.get('tempLockoutDuration')
					remainingcounter = info.get('remainingCounter')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def changephone_step1(
				self, profile, newphone, access_token=None,
				credentialid=None, rprequestid=None, requestid=None,
				agreementuuid=None, notificationtemplate=None, lang=''
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if self.user.bs is None and agreementuuid is None:
				raise Exception('agreementUUID is required.')

			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			# Step 1
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"requestType": "request",
				"credentialID": credentialid,
				"agreementUUID": agreementuuid,
				"newPhone": newphone,
				"notificationTemplate": notificationtemplate,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request(
				"POST", url + "credentials/changePhone",
				headers=headers, data=payload
			)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				self.user.responseid = info.get('responseID')

				class MyClass:
					responseid = info.get('responseID')
					tempLockDuration = info.get('tempLockDuration')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def changephone_step2(
				self, profile, otpoldphone, otpnewphone,
				access_token=None, credentialid=None, lang='',
				rprequestid=None, requestid=None, agreementuuid=None
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if requestid is None:
				requestid = self.user.responseid
				if requestid is None:
					raise Exception("Must do step 1.")

			if self.user.bs is None and agreementuuid is None:
				raise Exception('agreementUUID is required.')

			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"requestType": "confirm",
				"credentialID": credentialid,
				"agreementUUID": agreementuuid,
				"otpOldPhone": otpoldphone,
				"otpNewPhone": otpnewphone,
				"lang": lang,
				"profile": profile
			}
			response = requests.request(
				"POST", url + "credentials/changePhone",
				headers=headers, data=payload
			)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				self.user.responseid = info.get('responseID')

				class MyClass:
					reponseid = info.get('responseID')
					templckoutduration = info.get('tempLockoutDuration')
					remainingCounter = info.get('remainingCounter')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def issue(
				self, profile, certificateprofile, authmode, access_token=None, rprequestid=None,
				requestid=None, lang='', user=None, usertype=None, agreementuuid=None,
				signingprofile='UNLIMITED', signingprofilevalue=None, sharedmode='PRIVATE_MODE',
				scal=1, multisign=1, email=None, phone=None,
				commonname=None, organization=None, organizationunit=None, title=None,
				certemail=None, telephonenumber=None, location=None, stateorprovince=None,
				country=None, identype_value=None,
				notbefore=None, notafter=None, oprationmode='S', responseuri=None, certificates=None
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			if self.user.bs is None and (user is None or usertype is None):
				raise Exception('Both user and usertype required.')
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			idpair = []
			if identype_value is None:
				identype_value = {}
			for k, v in identype_value.items():
				idpair.append({'type': k, 'value': v})
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"user": user,
				"userType": usertype,
				"agreementUUID": agreementuuid,
				"certificateProfile": certificateprofile,
				"signingProfile": signingprofile,
				"signingProfileValue": signingprofilevalue,
				"sharedMode": sharedmode,
				"SCAL": scal,
				"authMode": authmode,
				"multisign": multisign,
				"email": email,
				"phone": phone,
				"certDetails": {
					"commonName": commonname,
					"organization": organization,
					"organizationUnit": organizationunit,
					"title": title,
					"email": certemail,
					"telephoneNumber": telephonenumber,
					"location": location,
					"stateOrProvince": stateorprovince,
					"country": country,
					"identifications": idpair
				},
				"notBefore": notbefore,
				"notAfter": notafter,
				"operationMode": oprationmode,
				"responseURI": responseuri,
				"certificates": certificates
			}
			payload = del_none(payload)
			payload = json.dumps(payload)
			response = requests.request("POST", url + "credentials/issue", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					certificates = info.get('certificates')
					csr = info.get('csr')
					credentialid = info.get('credentialID')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def renew(
				self, profile, credentialid=None, access_token=None,
				rprequestid=None, requestid=None, lang='', agreementuuid=None,
				certificateprofile=None, signingprofile=None, keepserialenabled=False,
				keepkeyenabled=False, personname=None, organization=None, organizationunit=None,
				title=None, email=None, telephonenumber=None, location=None,
				stateorprovine=None, country=None, notbefore=None, notafter=None,
				operationmode='S', responseuri=None, certificates=None
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"agreementUUID": agreementuuid,
				"credentialID": credentialid,
				"certificateProfile": certificateprofile,
				"signingProfile": signingprofile,
				"keepSerialEnabled": keepserialenabled,
				"keepKeyEnabled": keepkeyenabled,
				"certDetails": {
					"personName": personname,
					"organization": organization,
					"organizationUnit": organizationunit,
					"title": title,
					"email": email,
					"telephoneNumber": telephonenumber,
					"location": location,
					"stateOrProvince": stateorprovine,
					"country": country
				},
				"notBefore": notbefore,
				"notAfter": notafter,
				"operationMode": operationmode,
				"responseURI": responseuri,
				"certificates": certificates
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "credentials/renew", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					certificates = info.get('certificates')
					csr = info.get('csr')
					credentialid = info.get('credentialID')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

	class Signatures:
		def __init__(self, user):
			self.user = user

		def signhash(
				self, profile, message, SAD=None, access_token=None,
				rprequestid=None, requestid=None, lang='', agreementuuid=None,
				credentialid=None,
				hashalgorithoid='2.16.840.1.101.3.4.2.1', signalgo='1.2.840.113549.1.1.1',
				signalgoparams='BgkqhkiG9w0BAQo=', operationmode='S',
				scaidentity=None, instanceuuid=None, responseuri=None, validityperiod=None
		):
			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			if SAD is None:
				SAD = self.user.SAD
				if SAD is None:
					raise rssperrors.SADNotFound
			hashes = []
			for e in message:
				hashes.append(base64.b64encode(hashlib.sha256(e.encode('utf-8')).digest()).decode('utf-8'))

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}

			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"agreementUUID": agreementuuid,
				"credentialID": credentialid,
				"SAD": SAD,
				"documentDigests": {
					"hashes": hashes,
					"hashAlgorithmOID": hashalgorithoid
				},
				"signAlgo": signalgo,
				"signAlgoParams": signalgoparams,
				"operationMode": operationmode,
				"scaIdentity": scaidentity,
				"clientInfo": {
					"instanceUUID": instanceuuid
				},
				"responseURI": responseuri,
				"validityPeriod": validityperiod,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "signatures/signHash", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 3034 or info.get('error') == 0:
				self.user.responseid_signhash = info.get('responseID')

				class MySignHash:
					responseid = info.get('responseID')
					signatures = info.get('signatures')
					remainingsigningcounter = info.get('remainingSigningCounter')
					remainingcounter = info.get('remainingCounter')
					templockoutduration = info.get('tempLockoutDuration')

					def __str__(self):
						return str(info)
				return MySignHash()
			else:
				return response.json()
				# raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def signpolling(self, profile, requestid, access_token=None, rprequestid=None, lang=''):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if requestid is None:
				requestid = self.user.responseid_signhash
				if requestid is None:
					raise Exception('RequestID not found.')
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "signatures/signPolling", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError

			if info.get('error') == 0:
				class MySignPolling:
					responseid = info.get('responseID')
					documentwithsignature = info.get('documentWithSignature')
					signatureobject = info.get('signatureObject')
					signatures = info.get('signatures')
					remainingsigningcounter = info.get('remainingSigningCounter')
					remainingcounter = info.get('remainingCounter')
					templockoutduration = info.get('tempLockoutDuration')
					sad = info.get('SAD')
					expiresin = info.get('expiresIn')

					def __str__(self):
						return str(info)
				return MySignPolling()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

	class Owner:
		def __init__(self, user):
			self.user = user

		def list(
				self, profile, access_token=None, rprequestid=None,
				requestid=None, taxid=None, personaid=None,
				passportid=None, budgetid=None, lang=''
		):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"searchConditions": {
					"taxID": taxid,
					"personalID": personaid,
					"passportID": passportid,
					"budgetID": budgetid
				},
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/list", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					requestid = info.get('requestID')
					username = info.get('username')
					owneruuid = info.get('ownerUUID')
					personalname = info.get('personalName')
					companyname = info.get('companyName')
					taxid = info.get('taxID')
					personalid = info.get('personalID')
					phone = info.get('phone')
					email = info.get('email')
					oauth2 = info.get('oauth2')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(Exception(f"Error {info.get('error')}: {info.get('errorDescription')}"))

		def assign(
				self, relyingparty, agreementuuid, owneruuid,
				profile, rprequestid=None, requestid=None,
				lang='', access_token=None
		):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"relyingParty": relyingparty,
				"agreementUUID": agreementuuid,
				"ownerUUID": owneruuid,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/assign", headers=headers, data=payload)
			return response

		def syncanticloningotp(
				self, profile, usertype, user, access_token=None,
				rprequestid=None, requestid=None, lang='',
				notificationmessage=None, messagecaption=None,
				message=None, logouri=None, bgimageuri=None,
				rpiconuri=None, rpname=None, vcenabled=False,
				scaidentity=None, confirmationpolicy='PIN',
				hashes=None, hashalgorithmoid=None, validityperiod=None,
				operationmode='S', responseuri=None, notificationtemplate=None,
				notificationsubject=None
		):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"user": user,
				"userType": usertype,
				"lang": lang,
				"profile": profile,
				"tseNotification": {
					"notificationMessage": notificationmessage,
					"messageCaption": messagecaption,
					"message": message,
					"logoURI": logouri,
					"bgImageURI": bgimageuri,
					"rpIconURI": rpiconuri,
					"rpName": rpname,
					"vcEnabled": vcenabled,
					"scaIdentity": scaidentity,
					"confirmationPolicy": confirmationpolicy,
					"hashes": hashes,
					"hashAlgorithmOID": hashalgorithmoid
				},
				"validityPeriod": validityperiod,
				"operationMode": operationmode,
				"responseURI": responseuri,
				"notificationTemplate": notificationtemplate,
				"notificationSubject": notificationsubject
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/syncAnticloningOTP", headers=headers, data=payload)
			return response

		def changepassword(
				self, profile, oldpassword, newpassword,
				access_token=None, rprequestid=None, requestid=None, lang='',
		):
			if self.user.bs is None:
				raise Exception('Need log in with username')

			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"oldPassword": oldpassword,
				"newPassword": newpassword,
				"lang": lang,
				"profile": profile,
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/changePassword", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyChangePassword:
					responseid = info.get('responseID')
					remainingcounter = info.get('remainingCounter')
					templockoutduration = info.get('tempLockoutDuration')

					def __str__(self):
						return str(info)
				return MyChangePassword()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def resetpassword_step1(
				self, profile, user, usertype="USERNAME",
				access_token=None, rprequestid=None, requestid=None,
				notificationtemplate=None, notificationsubject=None, lang='',
		):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			# Step 1
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"requestType": "request",
				"user": user,
				"userType": usertype,
				"notificationTemplate": notificationtemplate,
				"notificationSubject": notificationsubject,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/resetPassword", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				self.user.responseid = info.get('responseID')

				class MyClass:
					responseid = info.get('responseID')
					templockoutduration = info.get('tempLockoutDuration')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def resetpassword_step2(
				self, user, authorizecode, profile, usertype='USERNAME',
				access_token=None, requestid=None, rprequestid=None,
				newpassword=None, notificationtemplate=None, notificationsubject=None, lang=''
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if requestid is None:
				requestid = self.user.responseid
				if requestid is None:
					raise Exception("Must do step 1.")

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			# Step 2
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"requestType": "confirm",
				"user": user,
				"userType": usertype,
				"authorizeCode": authorizecode,
				"newPassword": newpassword,
				"notificationTemplate": notificationtemplate,
				"notificationSubject": notificationsubject,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/resetPassword", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					templockoutduration = info.get('tempLockoutDuration')
					remainingcounter = info.get('remainingCounter')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def changeemail_step1(
				self, profile, newemail,
				access_token=None, rprequestid=None, requestid=None,
				notificationtemplate=None, notificationsubject=None, lang=''
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			# Step 1
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"requestType": "request",
				"newEmail": newemail,
				"notificationTemplate": notificationtemplate,
				"notificationSubject": notificationsubject,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/changeEmail", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				self.user.responseid = info.get('responseID')

				class MyClass:
					responseid = info.get('responseID')
					templockoutduration = info.get('tempLockoutDuration')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def changeemail_step2(
				self, profile, otpoldemail, otpnewemail,
				access_token=None, rprequestid=None,
				requestid=None, lang=''
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if requestid is None:
				requestid = self.user.responseid
				if requestid is None:
					raise Exception("Must do step 1.")

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			# Step 2
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"requestType": "confirm",
				"otpOldEmail": otpoldemail,
				"otpNewEmail": otpnewemail,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/changeEmail", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					templockoutduration = info.get('tempLockoutDuration')
					remainingcounter = info.get('remainingCounter')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def create(
				self, fullname, username, email, phone,
				identificationtype, identification, profile, twofactormethod=None,
				password=None, access_token=None, registertseenabled=False,
				rprequestid=None, requestid=None, lang=''
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"username": username,
				"password": password,
				"fullname": fullname,
				"email": email,
				"phone": phone,
				"identificationType": identificationtype,
				"identification": identification,
				"twoFactorMethod": twofactormethod,
				"registerTSEEnabled": registertseenabled,
				# "loa": loa,
				# "kycEvidence": kycevidence
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/create", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error'):
				class MyClass:
					responseid = info.get('responseID')
					deviceuuid = info.get('deviceUUID')
					owneruuid = info.get('ownerUUID')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def info(self, profile, access_token=None, rprequestid=None, requestid=None, lang='', user=None, usertype=None):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if self.user.bs is None and (user is None or usertype is None):
				raise Exception('Both user and usertype required.')
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"user": user,
				"userType": usertype,
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/info", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					state = info.get('state')
					username = info.get('username')
					fullname = info.get('fullname')
					email = info.get('email')
					phone = info.get('phone')
					identificationtype = info.get('identificationType')
					identification = info.get('identification')
					owneruuid = info.get('ownerUUID')
					twofactormethod = info.get('twoFactorMethod')
					tse_state = tse_model = tse_ostype = \
						tse_osversion = tse_version = tse_uafenabled = \
						tse_otpmobileenabled = tse_deviceuuid = None
					if info.get('tseInfo'):
						tse_state = info.get('tseInfo').get('state')
						tse_model = info.get('tseInfo').get('model')
						tse_ostype = info.get('tseInfo').get('osType')
						tse_osversion = info.get('tseInfo').get('osVersion')
						tse_version = info.get('tseInfo').get('version')
						tse_uafenabled = info.get('tseInfo').get('uafEnabled')
						tse_otpmobileenabled = info.get('tseInfo').get('otpMobileEnabled')
						tse_deviceuuid = info.get('tseInfo').get('deviceUUID')
					loa = info.get('loa')
					kycevidence = info.get('kycEvidence')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def changeinfo(
				self, profile, access_token=None, user=None,
				usertype=None, rprequestid=None, requestid=None, lang='',
				fullname=None, email=None, phone=None, identificationtype=None,
				identification=None, twofactormethod=None
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound

			if self.user.bs is None and (user is None or usertype is None):
				raise Exception('Both user and usertype required.')
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"user": user,
				"userType": usertype,
				"fullname": fullname,
				"email": email,
				"phone": phone,
				"identificationType": identificationtype,
				"identification": identification,
				"twoFactorMethod": twofactormethod
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/changeInfo", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def sendotp(
				self, profile, access_token=None, rprequestid=None,
				requestid=None, lang='', user=None, usertype=None,
				notificationtemplate=None, notificationsubject=None, otptype='EMAIL'
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			if self.user.bs is None and (user is None or usertype is None):
				raise Exception('Both user and usertype required.')
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"user": user,
				"userType": usertype,
				"notificationTemplate": notificationtemplate,
				"notificationSubject": notificationsubject,
				"otpType": otptype
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/sendOTP", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				self.user.responseid = info.get('responseID')

				class MyClass:
					responseid = info.get('responseID')
					templockoutduration = info.get('tempLockoutDuration')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def logging(
				self, profile, access_token=None, user=None,
				usertype=None, rprequestid=None, requestid=None, lang=None
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			if self.user.bs is None and (user is None or usertype is None):
				raise Exception('Both user and usertype required.')
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"user": user,
				"userType": usertype
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "owner/logging", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					client_relyingparty = client_loggedat = client_ip = client_macaddr = client_os = None
					if info.get('clientInfos'):
						client_relyingparty = info.get('clientInfos').get('relyingParty')
						client_loggedat = info.get('clientInfos').get('loggedAt')
						client_ip = info.get('clientInfos').get('ip')
						client_macaddr = info.get('clientInfos').get('macAddr')
						client_os = info.get('clientInfos').get('os')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

	class Agreements:
		def __init__(self, user):
			self.user = user

		def create(self, agreementuuid, profile, access_token=None, rprequestid=None, requestid=None, lang=''):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"agreementUUID": agreementuuid
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "agreements/create", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def assign(
				self, profile, access_token=None, rprequestid=None,
				requestid=None, lang='', agreementuuid=None, user=None,
				usertype=None, authorizecode=None, notificationmessage=None,
				messagecaption=None, message=None, logouri=None,
				bgimageuri=None, rpiconuri=None, rpname=None, vcenabled=False,
				scaidentity=None, confirmationpolicy=None, validityperiod=None,
				hashes=None, hashalgorithmoid="2.16.840.1.101.3.4.2.1"
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			if self.user.bs is None and (user is None or usertype is None):
				raise Exception('Both user and usertype required.')
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			if requestid is None:
				requestid = self.user.responseid
				if requestid is None:
					raise Exception('Need responseID from owner/sendOTP')
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"agreementUUID": agreementuuid,
				"user": user,
				"userType": usertype,
				"authorizeCode": authorizecode,
				"tseNotification": {
					"notificationMessage": notificationmessage,
					"messageCaption": messagecaption,
					"message": message,
					"logoURI": logouri,
					"bgImageURI": bgimageuri,
					"rpIconURI": rpiconuri,
					"rpName": rpname,
					"vcEnabled": vcenabled,
					"scaIdentity": scaidentity,
					"confirmationPolicy": confirmationpolicy,
					"validityPeriod": validityperiod,
					"hashes": hashes,
					"hashAlgorithmOID": hashalgorithmoid,
				}
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "agreements/assign", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					claims = info.get('claims')
					remainingcounter = info.get('remainingCounter')
					templockoutduration = info.get('tempLockoutDuration')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

	class Queries:
		def __init__(self, user):
			self.user = user

		def owner_history(
				self, profile, access_token=None, rprequestid=None,
				requestid=None, lang='', user=None, usertype=None, pagenumber=1,
				recordcount=100, fromdate=None, todate=None, actions=None, requestdata=False,
				responsedata=False, relyingparty=False, responsemessage=False,
				recordrprequestid=False, recordrequestid=False, responseid=None
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			if self.user.bs is None and (user is None or usertype is None):
				raise Exception('Both user and usertype required.')
			if actions is None:
				actions = ['ALL']
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"user": user,
				"userType": usertype,
				"pageNumber": pagenumber,
				"recordCount": recordcount,
				"searchConditions": {
					"fromDate": fromdate,
					"toDate": todate,
					"actions": actions
				},
				"record": {
					"requestData": requestdata,
					"responseData": responsedata,
					"relyingParty": relyingparty,
					"responseMessage": responsemessage,
					"rpRequestID": recordrprequestid,
					"requestID": recordrequestid,
					"responseID": responseid
				}
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "queries/owner/history", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					currentpage = info.get('currentPage')
					recordcount = info.get('recordCount')
					recordtotal = info.get('recordTotal')
					records = info.get('records')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def credential_history(
				self, profile, access_token=None, credentialid=None,
				rprequestid=None, requestid=None, lang='', agreementuuid=None,
				pagenumber=1, recordcount=100, fromdate=None, todate=None, actions=None,
				requestdata=False, responsedata=False, relyingparty=False,
				responsemessage=False, recordrprequestid=False,
				recordrequestid=False, recordresponseid=False
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			if credentialid is None:
				credentialid = self.user.credentialid
				if credentialid is None:
					raise rssperrors.CredentalIDNotFound
			if actions is None:
				actions = ['ALL']
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"agreementUUID": agreementuuid,
				"credentialID": credentialid,
				"pageNumber": pagenumber,
				"recordCount": recordcount,
				"searchConditions": {
					"fromDate": fromdate,
					"toDate": todate,
					"actions": actions
				},
				"record": {
					"requestData": requestdata,
					"responseData": responsedata,
					"relyingParty": relyingparty,
					"responseMessage": responsemessage,
					"rpRequestID": recordrprequestid,
					"requestID": recordrequestid,
					"responseID": recordresponseid,
				}
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "queries/credential/history", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					currentpage = info.get('currentPage')
					recordcount = info.get('recordCount')
					recordtotal = info.get('recordTotal')
					records = info.get('records')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

	class System:
		def __init__(self, user):
			self.user = user

		def getcertificateauthorities(
				self, profile, access_token=None, rprequestid=None,
				requestid=None, lang='', certificates='single'
			):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"certificates": certificates
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "systems/getCertificateAuthorities", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					certificateauthorities = info.get('certificateAuthorities')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def getcertificateprofiles(self, profile, caname, access_token=None, rprequestid=None, requestid=None, lang=''):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile,
				"caName": caname
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "systems/getCertificateProfiles", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					profiles = info.get('profiles')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def getsigningprofiles(self, profile, access_token=None, rprequestid=None, requestid=None, lang=''):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "systems/getSigningProfiles", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					profiles = info.get('profiles')
					name = info.get('profiles').get('name')
					signingcounter = info.get('profiles').get('signingCounter')
					amount = info.get('profiles').get('amount')
					type = info.get('profiles').get('type')
					desciption = info.get('profiles').get('description')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def getcountries(self, profile, access_token=None, rprequestid=None, requestid=None, lang=''):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "systems/getCountries", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					resposneid = info.get('responseID')
					countries = info.get('countries')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")

		def getstatesorprovinces(self, country, profile, rprequestid=None, requestid=None, lang='', access_token=None):
			if access_token is None:
				access_token = self.user.access_token
				if access_token is None:
					raise rssperrors.TokenNotFound
			headers = {
				'Authorization': f'Bearer {access_token}',
				'Content-Type': 'application/json'
			}
			payload = {
				"rpRequestID": rprequestid,
				"requestID": requestid,
				"lang": lang,
				"country": country,
				"profile": profile
			}
			payload = json.dumps(payload)
			response = requests.request("POST", url + "systems/getStatesOrProvinces", headers=headers, data=payload)
			try:
				info = response.json()
			except Exception:
				raise ConnectionError
			if info.get('error') == 0:
				class MyClass:
					responseid = info.get('responseID')
					provinces = info.get('provinces')

					def __str__(self):
						return str(info)
				return MyClass()
			else:
				raise Exception(f"Error {info.get('error')}: {info.get('errorDescription')}")
