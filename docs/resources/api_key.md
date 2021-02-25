---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "seq_api_key Resource - terraform-provider-seq"
subcategory: ""
description: |-
  Use this resource to create and manage API keys.
---

# seq_api_key (Resource)

Use this resource to create and manage API keys.

## Example Usage

```terraform
resource "seq_api_token" "example" {
  title = "example"
  token = "jdJfrXPcEuw72Jv260nz"
  assigned_permissions = [
    "Ingest",
  ]
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **title** (String) A title for the API key.

### Optional

- **assigned_permissions** (List of String) List of permissions assigned to the API key. Possible values are `Ingest`, `Read`, `Setup` and `Write`.
- **id** (String) The ID of this resource.
- **is_default** (Boolean) If `true`, the key is the built-in (tokenless) API key representing unauthenticated HTTP ingestion.
- **owner_id** (String) The id of the user for whom this is a personal API key.
- **token** (String, Sensitive) A pre-allocated API key token; by default, a new token will be generated.

### Read-Only

- **token_prefix** (String) A few characters from the start of the `token` stored as plain text, to aid in identifying tokens.

