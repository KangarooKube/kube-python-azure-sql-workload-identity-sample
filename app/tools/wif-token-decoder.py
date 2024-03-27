# this file will output the details of the Azure Federation Token 
# allowing for validation of things like issuer URL
import jwt
import os
wif_token = open(os.environ.get("AZURE_FEDERATED_TOKEN_FILE"), "r")
decoded_token = jwt.decode(wif_token.read(), options={"verify_signature": False})
print(decoded_token)