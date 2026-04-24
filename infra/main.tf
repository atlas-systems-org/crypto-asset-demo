resource "aws_kms_key" "main" {
  description = "Main encryption key"
  key_usage   = "ENCRYPT_DECRYPT"
}

resource "aws_kms_alias" "main" {
  name          = "alias/my-app-key"
  target_key_id = aws_kms_key.main.key_id
}
