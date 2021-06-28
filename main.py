import ast
import base64
import datetime
import hashlib
import json
from pprint import pprint

import requests
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from OpenSSL import crypto

from rssperrors import (AccountBlocked, AccountNotExisted, CredentalIDNotFound,
                        ExpiredRequest, InvalidLogin, MissingInfomation,
                        MobileAppNotReady, OptionError, TokenNotFound)

url = 'http://192.168.2.247:9080/rssp/v2/'
now = datetime.datetime.now()
timestamp = int(datetime.datetime.timestamp(now).__round__(3) * 1000)
content_type = 'application/json'


def info_rssp(profile):
    headers = {
        'Content-Type': content_type
    }
    json_payload = {
        'profile': profile
    }
    response = requests.request(
        'GET', 'http://192.168.2.247:9080/rssp/v2/info', headers=headers, data=json_payload)
    print(response.text)


class BaseInfo:
    @staticmethod
    def pkcssignature(username, password, signature):
        with open('materials/cloudfca.p12', 'rb') as source:
            p12 = crypto.load_pkcs12(source.read(), b'12345678')

        parsed_pem_key = crypto.dump_privatekey(
            crypto.FILETYPE_PEM, p12.get_privatekey())
        message = bytes(f'{username}{password}{signature}{timestamp}', 'utf-8')
        key = RSA.importKey(parsed_pem_key)
        h = SHA.new(message)
        signature = PKCS1_v1_5.new(key).sign(h)
        pkcssignature = base64.b64encode(signature).decode('utf-8')
        return pkcssignature

    @staticmethod
    def ssl(username, password, signature, pkcssignature):
        ssl = base64.b64encode(bytes(
            f'{username}:{password}:{signature}:{timestamp}:{pkcssignature}', 'utf-8')).decode('utf-8')
        return ssl


class GetTwoFactor:
    def __init__(self, username, password, signature, relyingparty, profile, user, usertype):
        self.username = username
        self.password = password
        self.signature = signature
        self.relyingparty = relyingparty
        self.profile = profile
        self.user = user
        self.usertype = usertype
        self.two_factor_method = None

    @property
    def pkcssignature(self):
        pkcssignature = BaseInfo.pkcssignature(
            self.username, self.password, self.signature)
        return pkcssignature

    @property
    def ssl(self):
        ssl = BaseInfo.ssl(self.username, self.password,
                           self.signature, self.pkcssignature)
        return ssl

    @property
    def headers(self):
        headers = {
            'authorization': f'SSL2 {self.ssl}',
            'Content-Type': content_type
        }
        return headers

    @property
    def payload(self):
        json_payload = {
            'profile': f'{self.profile}',
            'relyingParty': f'{self.relyingparty}',
            'user': f'{self.user}',
            'userType': f'{self.usertype}'
        }
        payload = json.dumps(json_payload)
        return payload

    def postrequests(self):
        response = requests.request(
            'POST', url + 'auth/getTwoFactorMethod',
            headers=self.headers, data=self.payload, timeout=10
        )
        codeerror = ast.literal_eval(response.text).get('error')
        if codeerror == 3003:
            raise AccountNotExisted
        elif codeerror == 3002:
            raise AccountBlocked

        self.two_factor_method = ast.literal_eval(
            response.text).get('twoFactorMethod')
        return response.json()

    def __repr__(self):
        return f'Twofactormethod user {self.username}'

    def __str__(self):
        return f'Get towfactor method for user {self.username}'


class AuthLogin:
    login = False
    get_credentialid = False

    def __init__(
        self, username, password, signature, relyingparty, profile, rememberme=None,
        rprequestid=None, requestid=None, iccid=None, imei=None, macaddr=None, lang="",
        notificationmessage=None, messagecaption=None, message=None, logouri=None,
        bgimageuri=None, rpiconuri=None, rpname=None, vcenabled=True,
        scaidentity=None, confirmationpolicy=None, validityperiod=None, hashes=None,
        hashalgorithmoid=None, user="", usertype=None, userpassword=None, tokentype=None,
        agreementuuid=None, certificatestatus="ALL", certificatepurpose="ALL",
        certinfo=False, certificates=None, authinfo=False, credentialid=None,
        notificationtemplate=None, notificationsubject=None, authorizecode=None, numsignatures=None,
        hashes_scal2=None, acenabled=False, instanceuuid=None, operationmode=None, responseuri=None,
        documents=None, signalgo=None, signalgoparams=None
    ):

        self.credentialid = credentialid
        self.username = username
        self.password = password
        self.signature = signature
        self.relyingparty = relyingparty
        self.profile = profile
        self.rememberme = rememberme
        self.rprequestid = rprequestid
        self.requestid = requestid
        self.iccid = iccid
        self.imei = imei
        self.macaddr = macaddr
        self.lang = lang
        self.notificationmessage = notificationmessage
        self.messagecaption = messagecaption
        self.message = message
        self.logouri = logouri
        self.bgimageuri = bgimageuri
        self.rpicouri = rpiconuri
        self.rpname = rpname
        self.vcenabled = vcenabled
        self.scaidentity = scaidentity
        self.confirmationpolicy = confirmationpolicy
        self.validityperiod = validityperiod
        self.hashes = hashes
        self.hashalgorithmoid = hashalgorithmoid
        self.user = user
        self.usertype = usertype
        self.userpassword = userpassword
        self.tokentype = tokentype
        self.agreementuuid = agreementuuid
        self.certificatestatus = certificatestatus
        self.certificatepurpose = certificatepurpose
        self.certinfo = certinfo
        self.certificates = certificates
        self.authinfo = authinfo
        self.notificationtemplate = notificationtemplate
        self.notificationsubject = notificationsubject
        self.authorizecode = authorizecode
        self.numsignatures = numsignatures
        self.hashes_scal2 = hashes_scal2
        self.acenabled = acenabled
        self.instanceuuid = instanceuuid
        self.operationmode = operationmode
        self.responseuri = responseuri
        self.documents = documents
        self.signalgo = signalgo
        self.signalgoparams = signalgoparams
        self.access_token, self.refresh_token = None, None
        self.SAD = None

    @property
    def pkcssignature(self):
        """Get Pkcs Signatute"""
        pkcssignature = BaseInfo.pkcssignature(
            self.username, self.password, self.signature)
        return pkcssignature

    @property
    def basic(self):
        if self.user != '' and self.usertype:
            basic = base64.b64encode(
                bytes(f'{self.usertype}:{self.user}:{self.userpassword}', 'utf-8'))
            return basic.decode('utf-8')

        return None

    @property
    def ssl(self):
        ssl = BaseInfo.ssl(self.username, self.password,
                           self.signature, self.pkcssignature)
        return ssl

    @property
    def headers_get_token(self):
        if not self.basic:
            headers = {
                'authorization': f'SSL2 {self.ssl}',
                'Content-Type': content_type
            }
            return headers

        return {
            'authorization': f'SSL2 {self.ssl}, basic {self.basic}',
            'Content-Type': content_type
        }

    def check_notimessage(self):
        check = GetTwoFactor(
            username=self.username, password=self.password, signature=self.signature,
            relyingparty=self.relyingparty, profile=self.profile, user=self.user,
            usertype=self.usertype
        )
        check.postrequests()
        if check.two_factor_method == 'TSE' and not self.notificationmessage:
            raise MissingInfomation

    @property
    def payload_get_token(self):
        if self.user and self.usertype:
            self.check_notimessage()
        json_payload = {
            'relyingParty': self.relyingparty,
            'profile': self.profile,
            'rememberMe': self.rememberme,
            'rpRequestID': self.rprequestid,
            'requestID': self.requestid,
            'clientInfo': {
                'iccid': self.iccid,
                'imei': self.imei,
                'macAddr': self.macaddr
            },
            'lang': self.lang,
            'tseNotification': {
                'notificationMessage': self.notificationmessage,
                'messageCaption': self.messagecaption,
                'message': self.message,
                'logoURI': self.logouri,
                'bgImageURI': self.bgimageuri,
                'rpIconURI': self.rpicouri,
                'rpName': self.rpname,
                'vcEnabled': self.vcenabled,
                'scaIdentity': self.scaidentity,
                'confirmationPolicy': self.confirmationpolicy,
                'validityPeriod': self.validityperiod,
                'hashes': self.hashes,
                'hashAlgorithmOID': self.hashalgorithmoid
            }
        }
        payload = json.dumps(json_payload)
        return payload

    def get_token(self):
        response = requests.request(
            'POST', url + 'auth/login', headers=self.headers_get_token,
            data=self.payload_get_token
        )
        info = response.text
        try:
            codeerror = ast.literal_eval(info).get('error')
            if codeerror == 3000:
                raise InvalidLogin
            if codeerror == 3213:
                raise MobileAppNotReady
            if codeerror == 3036:
                raise ExpiredRequest
            else:
                self.access_token, self.refresh_token = ast.literal_eval(info).get('accessToken'), \
                    ast.literal_eval(info).get('refreshToken')
                self.login = True

        except KeyError:
            raise TokenNotFound

        return response.json()

    @property
    def headers_final(self):
        if not self.login:
            self.get_token()
        return {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': content_type
        }

    @property
    def payload_finalize(self):
        json_payload = {
            'authorizeCode': self.authorizecode,
            'profile': self.profile,
        }
        payload = json.dumps(json_payload)
        return payload

    def finalizelogin(self):
        response = requests.request(
            'POST', url + 'auth/finalizeLogin', headers=self.headers_final,
            data=self.payload_finalize
        )

        # Add exception
        # codeerror = ast.literal_eval(response.text)['error']
        # if codeerror == 3000:
        #     raise InvalidLogin

        return response.text

    @property
    def payload_authrevoke(self):
        if self.tokentype == 1:
            json_payloadrevoke = {
                'tokenType': 1,
                'rpRequestID': self.rprequestid,
                'requestID': self.requestid,
                'token': self.refresh_token,
                'lang': self.lang,
                'agreementUUID': self.agreementuuid,
                'credentialID': self.credentialid,
                'profile': self.profile
            }

        elif self.tokentype == 0:
            json_payloadrevoke = {
                'tokenType': 0,
                'rpRequestID': self.rprequestid,
                'requestID': self.requestid,
                'token': self.access_token,
                'lang': self.lang,
                'agreementUUID': self.agreementuuid,
                'credentialID': self.credentialid,
                'profile': self.profile
            }
        else:
            raise OptionError

        payload = json.dumps(json_payloadrevoke)
        return payload

    def authrevoke(self, tokentype=0):
        self.tokentype = tokentype
        if not self.login:
            self.get_token()  # get bearer-token and body-token at the same time

        if not self.get_credentialid:
            self.credentiallist()

        response = requests.request(
            'POST', url + 'auth/revoke',
            headers=self.headers_final,
            data=self.payload_authrevoke
        )
        return response.json()

    @property
    def payload_credential_list(self):
        json_payload = {
            "profile": self.profile,
            "rpRequestID": self.rprequestid,
            "requestID": self.requestid,
            "agreementUUID": self.agreementuuid,
            "searchConditions": {
                "certificateStatus": self.certificatestatus,
                "certificatePurpose": self.certificatepurpose
            },
            "certInfo": self.certinfo,
            "certificates": self.certificates,
            "authInfo": self.authinfo,
            "lang": self.lang
        }
        payload = json.dumps(json_payload)
        return payload

    def credentiallist(self, certificatestatus="ALL", certificatepurpose="ALL"):
        """ Get credentialID """
        self.certificatestatus = certificatestatus
        self.certificatepurpose = certificatepurpose

        if not self.login:
            self.get_token()

        response = requests.request("POST", url + "credentials/list", headers=self.headers_final,
                                    data=self.payload_credential_list)
        try:
            self.credentialid = ast.literal_eval(response.text).get("certs")[
                0].get("credentialID")
            self.get_credentialid = True
        except KeyError:
            raise CredentalIDNotFound

        return response

    @property
    def payload_credential_info(self):
        if not self.get_credentialid:
            self.credentiallist()

        json_payload = {
            'rpRequestID': self.rprequestid,
            'requestID': self.requestid,
            'lang': self.lang,
            'agreementUUID': self.agreementuuid,
            'credentialID': self.credentialid,
            'certificates': self.certificates,
            'certInfo': self.certinfo,
            'authInfo': self.authinfo,
            'profile': self.profile
        }
        payload = json.dumps(json_payload)
        return payload

    def credentialinfo(self, certificate='single'):
        self.certificates = certificate
        if not self.get_token:
            self.get_token()

        response = requests.request(
            'POST', url + 'credentials/info', headers=self.headers_final,
            data=self.payload_credential_info
        )
        return response.json()

    @property
    def payload_credential_sendotp(self):
        if not self.get_credentialid:
            self.credentiallist()

        json_payload = {
            'rpRequestID': self.rprequestid,
            'requestID': self.requestid,
            'agreementUUID': self.agreementuuid,
            'credentialID': self.credentialid,
            'notificationTemplate': self.notificationtemplate,
            'notificationSubject': self.notificationsubject,
            'lang': self.lang,
            'profile': self.profile
        }
        payload = json.dumps(json_payload)
        return payload

    def credential_sendotp(self):
        if not self.login:
            self.get_token()

        response = requests.request(
            'POST', url + 'credentials/sendOTP', headers=self.headers_final,
            data=self.payload_credential_sendotp
        )
        return response

    @property
    def payload_credentials_authorize(self):
        if not self.get_credentialid:
            self.credentiallist()

        json_payload = {
            'rpRequestID': self.rprequestid,
            'requestID': self.requestid,
            'agreementUUID': self.agreementuuid,
            'credentialID': '1d71077decd03620190cb4175ad667168ab0ad1b',  # self.credentialid
            'authorizeCode': self.authorizecode,
            'lang': '',
            'numSignatures': self.numsignatures,
            'documentDigests': {
                'hashes': self.hashes,
                'hashAlgorithmOID': self.hashalgorithmoid
            },
            'clientInfo': {
                'iccid': self.iccid,
                'imei': self.imei,
                'macAddr': self.macaddr,
                'instanceUUID': self.instanceuuid
            },
            'notificationMessage': self.notificationmessage,
            'messageCaption': self.messagecaption,
            'message': self.message,
            'logoURI': self.logouri,
            'bgImageURI': self.bgimageuri,
            'rpIconURI': self.rpicouri,
            'rpName': self.rpname,
            'confirmationPolicy': 'PIN',
            'vcEnabled': self.vcenabled,
            'acEnabled': self.acenabled,
            'operationMode': 'S',
            'scaIdentity': self.scaidentity,
            'responseURI': self.responseuri,
            'validityPeriod': self.validityperiod,
            'profile': self.profile,
            'documents': self.documents,
            'signAlgo': self.signalgo,
            'signAlgoParams': self.signalgoparams
        }
        payload = json.dumps(json_payload)
        return payload

    def credential_authorize(self, numsignatures=3):
        self.numsignatures = numsignatures
        if not self.login:
            self.get_token()

        response = requests.request(
            'POST', url + 'credentials/authorize', headers=self.headers_final,
            data=self.payload_credentials_authorize
        )
        try:
            self.SAD = ast.literal_eval(response.text)['SAD']
        except (SyntaxError, KeyError):
            raise ConnectionError('can not connect to server')
        return response

    @property
    def credentials_extendtransaction_payload(self):
        self.credential_authorize()

        json_payload = {
            'rpRequestID': self.rprequestid,
            'requestID': self.requestid,
            'agreementUUID': self.agreementuuid,
            'credentialID': '1d71077decd03620190cb4175ad667168ab0ad1b',
            'SAD': self.SAD,
            'lang': '',
            'documentDigests': {
                'hashes': self.hashes,
                'hashAlgorithmOID': self.hashalgorithmoid
            },
            'clientInfo': {
                'iccid': self.iccid,
                'imei': self.imei,
                'macAddr': self.macaddr,
                'instanceUUID': self.instanceuuid
            },
            'notificationMessage': self.notificationmessage,
            'messageCaption': self.messagecaption,
            'message': self.message,
            'logoURI': self.logouri,
            'bgImageURI': self.bgimageuri,
            'rpIconURI': self.rpicouri,
            'rpName': self.rpname,
            'confirmationPolicy': 'PIN',
            'vcEnabled': self.vcenabled,
            'acEnabled': self.acenabled,
            'operationMode': 'S',
            'scaIdentity': self.scaidentity,
            'responseURI': self.responseuri,
            'validityPeriod': self.validityperiod,
            'profile': self.profile,
            'documents': self.documents,
            'signAlgo': self.signalgo,
            'signAlgoParams': self.signalgoparams
        }
        payload = json.dumps(json_payload)
        return payload

    def credentials_extendtransaction(self):
        if not self.login:
            self.get_token()

        response = requests.request(
            'POST', url + 'credentials/extendTransaction', headers=self.headers_final,
            data=self.credentials_extendtransaction_payload
        )
        self.SAD = ast.literal_eval(response.text)['SAD']
        return response

    @property
    def signhash_payload(self):
        self.credentials_extendtransaction()
        h = hashlib.sha256(bytes(self.message, 'utf-8')).hexdigest()
        self.hashes = base64.b64encode(bytes(h, 'utf-8')).decode('utf-8')
        json_payload = {
            'rpRequestID': None,
            'requestID': None,
            'lang': '',
            'agreementUUID': None,
            'credentialID': '1d71077decd03620190cb4175ad667168ab0ad1b',
            'SAD': self.SAD,
            'documentDigests': {
                'hashes': ['M00Bb3Vc1txYxTqG4YOIL47BT1L7BTRYh8il7dQsh7c='],
                'hashAlgorithmOID': '2.16.840.1.101.3.4.2.1'
            },
            'signAlgo': '1.2.840.113549.1.1.1',
            'signAlgoParams': 'BgkqhkiG9w0BAQo=',
            'operationMode': 'S',
            'scaIdentity': self.scaidentity,
            'clientInfo': {
                'instanceUUID': self.instanceuuid
            },
            'responseURI': self.responseuri,
            'validityPeriod': self.validityperiod,
            'profile': self.profile
        }
        payload = json.dumps(json_payload)
        return payload

    def signhash(self, message):
        self.message = message
        if not self.login:
            self.get_token()

        response = requests.request(
            'POST', url + 'signatures/signHash', headers=self.headers_final,
            data=self.signhash_payload
        )
        return response


user1 = AuthLogin(
    username='TRUONGNNT_RP', certinfo=True,
    password='12345678', signature='aCiPiDxEIfoWajqE'
                                   '+k4CCnf0pUcLi7NxgNGq5hQYC26RtD'
                                   '+oauzwYblLU5oRTUM7YhLsfzXlCJ6VSgTFQze8vYw5x'
                                   '0ct4ReB5jP+1kb1RoCP+BT4rjQYxWhsWlF5h6RhER24C'
                                   'zFLUx4hv4TssxuHNq9WtDcEIZww17qe8KkMGPjTy7xQ'
                                   'PkxJLIaf9c1ZPymrhfINa0wytDSSYY4NZH5YvuJfoAGZ'
                                   'sRfuoyRbwxxoDteVRl5eQ/QyJtrHNRVMYBEkg+ONzsS'
                                   '4KRX9dnmk0A1oJYPA63m6ppXHsx3TZtxGieS0uYUyY'
                                   'fMTQlySo65TwlM7ZsH+hu5twqYv4kio3jPSpQ==',
    relyingparty='TRUONGNNT_RP', authorizecode='12345678',
    profile='rssp-119.432-v2.0', user='truongnnt',
    usertype='USERNAME', tokentype=1,
    userpassword='T@mic@8x', notificationmessage='abcd',
    rememberme=True
)

# Test---
# pprint(user1.get_token())
