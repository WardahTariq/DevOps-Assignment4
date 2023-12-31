# Output IAM user's access key, secret key, password and account_id
output "credentials" {
  value = {
      "key"      = aws_iam_access_key.terraform_user_key.id
      "secret"   = aws_iam_access_key.terraform_user_key.secret
      "password" = data.pgp_decrypt.user_password_decrypt.plaintext
      "account_id" = data.aws_caller_identity.current.account_id
  }
  sensitive = true
}
