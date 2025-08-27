# Example: Verify JWT

Here's an isolated example of provisioning AWS resources, creating a JWT token and verifying its signature.

## Provision AWS Resources

Authenticate into AWS:
```bash
aws sso login --profile=PowerUserAccess-787115532564
```

Create the test resources and export some env vars:j
```bash
cd terraform

terraform init
terraform apply -auto-approve

export COGNITO_JWKS_URL=$(terraform output -raw cognito_jwks_url)
export COGNITO_DOMAIN=$(terraform output -raw cognito_domain)
export COGNITO_USER_POOL_ID=$(terraform output -raw cognito_user_pool_id)
export CLIENT_ID=$(terraform output -raw client_id)
export CLIENT_SECRET=$(terraform output -raw client_secret)
```

## Create a JWT Token

Mint a new token:
```bash
TOKEN_RESP=$(curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n ${CLIENT_ID}:${CLIENT_SECRET} | base64)" \
  -d "grant_type=client_credentials&scope=http://localhost:7357/v1/test/read http://localhost:7357/v1/test/write" \
  https://${COGNITO_DOMAIN}.auth.us-east-1.amazoncognito.com/oauth2/token)

echo $TOKEN_RESP | jq .

export ACCESS_TOKEN=$(echo $TOKEN_RESP | jq .access_token -r)
```

## Verify the JWT

Run:
```bash
go run main.go
```

Expected output format (your key IDs and token would be different):
```bash
Successfully reconstructed 2 public keys from JWKS:
- Key ID: Jy3kjdiAh8nuL9pK4Pl1uJ69q/XMIWhBNpfIXluDZSU=, Modulus size: 2048 bits
- Key ID: OOtUe0gydbwqe60YVl2o2rfikPh0rz6yDLgeU/OAIKU=, Modulus size: 2048 bits

JWT: eyJraWQiOiJPT3RVZTBneWRid3FlNjBZVmwybzJyZmlrUGgwcno2eURMZ2VVXC9PQUlLVT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIzNDA3MnBqNDBnM3M2Z3VyMDlncGVzaXJjaiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiaHR0cDpcL1wvbG9jYWxob3N0OjczNTdcL3YxXC90ZXN0XC9yZWFkIGh0dHA6XC9cL2xvY2FsaG9zdDo3MzU3XC92MVwvdGVzdFwvd3JpdGUiLCJhdXRoX3RpbWUiOjE3NTYyNjQwOTQsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX01Zd0xqVm1FMCIsImV4cCI6MTc1NjI2NzY5NCwiaWF0IjoxNzU2MjY0MDk0LCJ2ZXJzaW9uIjoyLCJqdGkiOiIzYTg1YmVhYi1iYzM3LTQ2MjUtYTUyZC0zNjRjOTk0NGUyNGMiLCJjbGllbnRfaWQiOiIzNDA3MnBqNDBnM3M2Z3VyMDlncGVzaXJjaiJ9.DKXHLAFaFPrNixYrCyOqbT-SBK6lkxL76IEK2qIJoq3-36AVHqJ-FMUgtIa0sy4KPL6X40mVF8B-Z1HEh98MPJUPzXmW0MPN-xDjigic_a4oZi7cTat9IbJZF4FBMUNkkL9bWdMSeOU13fffKoZp2dgfKU52gV985BwhPIr34krchzC-SM3OyatZU1bIbako4fwCRAg69Q2dQLvAzrptw7hKO9KvBOgRp6RobOyowSOqGRbN_tuq8Jc0ci66VPEmdNXQoCdTC_Q4hRQAhtSoh3B5pDr82vJqr5RPaD0aECHVd0lObDJ1a3gsomXZvaQytif-UVToIhQ34dOVPp_tLA

Is token valid? true
```
