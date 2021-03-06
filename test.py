for i in range(3):
    globals()[f'list_{i}'] = []

dict = {'error': 0,
        'errorDescription': 'SUCCESSFULLY',
        'profiles': [{'algorithm': 'SHA256WITHRSA2048E16',
                      'attributes': [{'attributeType': 'RADIO_BUTTON',
                                      'attributes': [{'attributeType': 'TEXT_FIELD',
                                                      'description': 'PERSONAL ID',
                                                      'name': '0.9.2342.19200300.100.1.1',
                                                              'prefix': 'CMND:',
                                                              'require': False},
                                                     {'attributeType': 'TEXT_FIELD',
                                                      'description': 'PASSPORT ID',
                                                      'name': '0.9.2342.19200300.100.1.1',
                                                              'prefix': 'HC:',
                                                              'require': False},
                                                     {'attributeType': 'TEXT_FIELD',
                                                      'description': 'CITIZEN ID',
                                                      'name': '0.9.2342.19200300.100.1.1',
                                                              'prefix': 'CCCD:',
                                                              'require': False}],
                                      'description': 'Personal ID',
                                      'name': 'CMND',
                                      'prefix': 'CMND:',
                                      'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Personal Name',
                                      'name': 'CN',
                                              'prefix': '',
                                      'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Email Address in DN',
                                      'name': 'E',
                                              'prefix': '',
                                      'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Telephone Number',
                                      'name': 'telephoneNumber',
                                              'prefix': '',
                                      'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Locality',
                                      'name': 'L',
                                              'prefix': '',
                                      'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'State or Province',
                                      'name': 'ST',
                                              'prefix': '',
                                      'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Country (ISO 3166)',
                                      'name': 'C',
                                              'prefix': '',
                                      'require': True}],
                      'description': 'T2PSB23Y',
                      'duration': 100,
                      'name': 'T2PSB23Y',
                      'promotionDuration': 100,
                      'type': 'PERSONAL'},
                     {'algorithm': 'SHA256WITHRSA2048E16',
                      'attributes': [{'attributeType': 'RADIO_BUTTON',
                                      'attributes': [{'attributeType': 'TEXT_FIELD',
                                                      'description': 'TAX CODE',
                                                      'name': '0.9.2342.19200300.100.1.1',
                                                      'prefix': 'MST:',
                                                              'require': False},
                                                     {'attributeType': 'TEXT_FIELD',
                                                      'description': 'BUDGET ID',
                                                      'name': '0.9.2342.19200300.100.1.1',
                                                      'prefix': 'MNS:',
                                                              'require': False}],
                                      'description': 'Enterprise ID',
                                      'name': 'MST',
                                              'prefix': 'MST:',
                                      'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Company Name',
                                      'name': 'CN',
                                              'prefix': '',
                                              'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Organization',
                                      'name': 'O',
                                              'prefix': '',
                                              'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Organization Unit',
                                      'name': 'OU',
                                              'prefix': '',
                                              'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Email Address in DN',
                                      'name': 'E',
                                              'prefix': '',
                                              'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Telephone Number',
                                      'name': 'telephoneNumber',
                                              'prefix': '',
                                              'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Locality',
                                      'name': 'L',
                                              'prefix': '',
                                              'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'State or Province',
                                      'name': 'ST',
                                              'prefix': '',
                                              'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Country (ISO 3166)',
                                      'name': 'C',
                                              'prefix': '',
                                              'require': True}],
                      'description': 'T2OSB23Y',
                      'duration': 365,
                      'name': 'T2OSB23Y',
                      'promotionDuration': 365,
                      'type': 'ENTERPRISE'},
                     {'algorithm': 'SHA256WITHRSA2048E16',
                      'attributes': [{'attributeType': 'RADIO_BUTTON',
                                      'attributes': [{'attributeType': 'TEXT_FIELD',
                                                      'description': 'TAX CODE',
                                                      'name': '0.9.2342.19200300.100.1.1',
                                                      'prefix': 'MST:',
                                                              'require': False},
                                                     {'attributeType': 'TEXT_FIELD',
                                                      'description': 'BUDGET ID',
                                                      'name': '0.9.2342.19200300.100.1.1',
                                                      'prefix': 'MNS:',
                                                              'require': False}],
                                      'description': 'Enterprise ID',
                                      'name': 'MST',
                                              'prefix': 'MST:',
                                      'require': True},
                                     {'attributeType': 'RADIO_BUTTON',
                                      'attributes': [{'attributeType': 'TEXT_FIELD',
                                                      'description': 'PERSONAL ID',
                                                      'name': '0.9.2342.19200300.100.1.1',
                                                      'prefix': 'CMND:',
                                                      'require': False},
                                                     {'attributeType': 'TEXT_FIELD',
                                                      'description': 'PASSPORT ID',
                                                      'name': '0.9.2342.19200300.100.1.1',
                                                      'prefix': 'HC:',
                                                      'require': False},
                                                     {'attributeType': 'TEXT_FIELD',
                                                      'description': 'CITIZEN ID',
                                                      'name': '0.9.2342.19200300.100.1.1',
                                                      'prefix': 'CCCD:',
                                                      'require': False}],
                                      'description': 'Personal ID',
                                      'name': 'CMND',
                                              'prefix': 'CMND:',
                                      'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Personal Name',
                                      'name': 'CN',
                                              'prefix': '',
                                              'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Organization',
                                      'name': 'O',
                                              'prefix': '',
                                              'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Organization Unit',
                                      'name': 'OU',
                                              'prefix': '',
                                              'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Title',
                                      'name': 'T',
                                              'prefix': '',
                                              'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Email Address in DN',
                                      'name': 'E',
                                              'prefix': '',
                                              'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Telephone Number',
                                      'name': 'telephoneNumber',
                                              'prefix': '',
                                              'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Locality',
                                      'name': 'L',
                                              'prefix': '',
                                              'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'State or Province',
                                      'name': 'ST',
                                              'prefix': '',
                                              'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Country (ISO 3166)',
                                      'name': 'C',
                                              'prefix': '',
                                              'require': True}],
                      'description': 'T2SFB23Y',
                      'duration': 1095,
                      'name': 'T2SFB23Y',
                      'promotionDuration': 1095,
                      'type': 'STAFF'},
                     {'algorithm': 'SHA256WITHRSA2048E16',
                      'attributes': [{'attributeType': 'RADIO_BUTTON',
                                      'attributes': [{'attributeType': 'TEXT_FIELD',
                                                      'description': 'TAX CODE',
                                                      'name': '0.9.2342.19200300.100.1.1',
                                                      'prefix': 'MST:',
                                                              'require': False},
                                                     {'attributeType': 'TEXT_FIELD',
                                                      'description': 'BUDGET ID',
                                                      'name': '0.9.2342.19200300.100.1.1',
                                                      'prefix': 'MNS:',
                                                              'require': False}],
                                      'description': 'Enterprise ID',
                                      'name': 'MST',
                                              'prefix': 'MST:',
                                      'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Company Name',
                                      'name': 'CN',
                                              'prefix': '',
                                              'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Organization',
                                      'name': 'O',
                                              'prefix': '',
                                              'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Organization Unit',
                                      'name': 'OU',
                                              'prefix': '',
                                              'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Email Address in DN',
                                      'name': 'E',
                                              'prefix': '',
                                              'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Telephone Number',
                                      'name': 'telephoneNumber',
                                              'prefix': '',
                                              'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Locality',
                                      'name': 'L',
                                              'prefix': '',
                                              'require': False},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'State or Province',
                                      'name': 'ST',
                                              'prefix': '',
                                              'require': True},
                                     {'attributeType': 'TEXT_FIELD',
                                      'description': 'Country (ISO 3166)',
                                      'name': 'C',
                                              'prefix': '',
                                              'require': True}],
                      'description': 'T2OSB21Y',
                      'duration': 365,
                      'name': 'T2OSB21Y',
                      'promotionDuration': 0,
                      'type': 'ENTERPRISE'}],
        'responseID': 'TRUONGNNT_RP-201008171426-565206-171345'
        }

t1 = (100,)
