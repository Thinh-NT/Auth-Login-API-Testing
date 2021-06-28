class MissingInfomation(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f'My client, {self.message} '
		else:
			return 'Error "2001", some informations missed'


class ConectionError(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f"My client, connection failed"

class AccountNotExisted(Exception):
	def __init__(self, message, errors):
		super(AccountNotExisted, self).__init__(message)
		self.errors = errors

	def __str__(self):
		return 'Error "3003", Account is not existed'

class InvalidParameter(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f'My client, {self.message} '
		else:
			return 'Parameter is invalid'

class InvalidLogin(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f'My client, {self.message} '
		else:
			return 'Erorr "3000", Login is invalid'

class AccountBlocked(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f'My client, {self.message} '
		else:
			return 'Error "3002", Account is blocked'

class MobileAppNotReady(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f'My client, {self.message} '
		else:
			return 'Error "3213", THE MOBILE APP IS NOT READY'

class ExpiredRequest(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f'My client, {self.message} '
		else:
			return 'Error "3036", REQUEST IS ALREADY EXPIRED'

class RefreshTokenNotFound(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f'My client, {self.message} '
		else:
			return 'Error "2002", Refresh token is not found'

class AccessTokenNotFound(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f'My client, {self.message} '
		else:
			return 'Error "2003", Access token is not found'

class OptionError(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f'My client, {self.message} '
		else:
			return 'Error "2004", Option is not available'

class TokenNotFound(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f'My client, {self.message} '
		else:
			return 'Error "2005", Token is not found'

class CredentalIDNotFound(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f'My client, {self.message} '
		else:
			return 'Error "2006", CredentialID is not found'

class SADNotFound(Exception):
	def __init__(self, *args):
		if args:
			self.message = args[0]
		else:
			self.message = None

	def __str__(self):
		if self.message:
			return f'My client, {self.message} '
		else:
			return 'Error "2007", SAD is not found'