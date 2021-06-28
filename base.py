import datetime
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from OpenSSL import crypto
from Crypto.Signature import PKCS1_v1_5
import base64

url = 'http://192.168.2.247:9080/rssp/v2/'
now = datetime.datetime.now()
timestamp = int(datetime.datetime.timestamp(now).__round__(3) * 1000)


class BaseInfo:
	@staticmethod
	def pkcssignature(username, password, signature):
		with open('materials/cloudfca.p12', 'rb') as source:
			p12 = crypto.load_pkcs12(source.read(), b'12345678')

		parsed_pem_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
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

def del_none(d):
	for key, value in list(d.items()):
		if value is None:
			del d[key]
		elif isinstance(value, dict):
			del_none(value)
	return d