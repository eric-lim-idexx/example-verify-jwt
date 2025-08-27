terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
  profile = "PowerUserAccess-787115532564"
}

# NOTE: random suffix is used to avoid conflicts with other resources
resource "random_string" "random_suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_cognito_user_pool" "example_verify_jwt" {
  name = "Test M2M User Pool ${random_string.random_suffix.result}"
}

resource "aws_cognito_user_pool_domain" "example_verify_jwt" {
  domain       = "example-verify-jwt-${random_string.random_suffix.result}"
  user_pool_id = aws_cognito_user_pool.example_verify_jwt.id
}

resource "aws_cognito_resource_server" "example_verify_jwt" {
  identifier   = "http://localhost:7357/v1/test"
  name         = "Test Resource Server ${random_string.random_suffix.result}"
  user_pool_id = aws_cognito_user_pool.example_verify_jwt.id

  scope {
    scope_name        = "read"
    scope_description = "Test read scope"
  }

  scope {
    scope_name        = "write"
    scope_description = "Test write scope"
  }
}

resource "aws_cognito_user_pool_client" "example_verify_jwt" {
  name            = "Test Client ${random_string.random_suffix.result}"
  user_pool_id    = aws_cognito_user_pool.example_verify_jwt.id
  generate_secret = true

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_scopes = [
    "${aws_cognito_resource_server.example_verify_jwt.identifier}/read",
    "${aws_cognito_resource_server.example_verify_jwt.identifier}/write",
  ]

  access_token_validity = 60
  token_validity_units {
    access_token = "minutes"
  }
}

output "cognito_jwks_url" {
  value = "https://cognito-idp.${aws_cognito_user_pool.example_verify_jwt.region}.amazonaws.com/${aws_cognito_user_pool.example_verify_jwt.id}/.well-known/jwks.json"
}
output "cognito_domain" {
  value = aws_cognito_user_pool_domain.example_verify_jwt.domain
}
output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.example_verify_jwt.id
}
output "client_id" {
  value = aws_cognito_user_pool_client.example_verify_jwt.id
}
output "client_secret" {
  value = nonsensitive(aws_cognito_user_pool_client.example_verify_jwt.client_secret)
}
output "available_scopes" {
  value = aws_cognito_user_pool_client.example_verify_jwt.allowed_oauth_scopes
}
