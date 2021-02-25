resource "seq_user" "example" {
  username      = "example"
  password      = "Password@123"
  display_name  = "Example user"
  email_address = "user@example.com"
  role_ids = [
    "role-user",
  ]
  must_change_password = true
}
