def create_credential(gmp, username, password, CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY):
    credential_response = gmp.create_credential(
        name='scanner_credential',
        credential_type=gmp.types.CredentialType.CLIENT_CERTIFICATE,
        login=username,
        password=password,
        certificate=open(CLIENT_CERTIFICATE).read(),
        private_key=open(CLIENT_PRIVATE_KEY).read()
    )
    if credential_response.get('status_text') == "Credential exists already":
        credentialList = gmp.get_credentials()
        return credentialList[0].get('id')
    else:
        return credential_response.get('id')
