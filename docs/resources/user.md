---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "seq_user Resource - terraform-provider-seq"
subcategory: ""
description: |-
  Use this resource to create a user on the Seq server.
---

# seq_user (Resource)

Use this resource to create a user on the Seq server.

## Example Usage

```terraform
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
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **password** (String, Sensitive) The password for the user.
- **username** (String) The username that uniquely identifies the user.

### Optional

- **display_name** (String) An optional display name to aid in identifying the user.
- **email_address** (String) The user's email address. This will be used to show a Gravatar for the user in some situations.
- **id** (String) The ID of this resource.
- **must_change_password** (Boolean) If `true`, the user will be unable to log in without first changing their password. Recommended when administratively assigning a password for the user.
- **role_ids** (List of String) The ids of one or more roles that grant permissions to the user. Possible values are `role-administrator` (Administrator), `role-ro` (User, read-only), `role-rw` (User, read/write) and `role-user` (User, read/write/ingest)`.

