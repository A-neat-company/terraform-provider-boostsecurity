---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "boostsecurity_fortify Resource - boostsecurity"
subcategory: ""
description: |-
  Manages Scanner coverage.
---

# boostsecurity_fortify (Resource)

Manages Scanner coverage.

## Example Usage

```terraform
# Manage example asset
resource "boostsecurity_fortify" "example" {
  asset = {
    provider   = "<GitHub|GitLab|Azure DevOps|Bitbucket>"
    collection = "<Full path to up to the resource>"
    resource   = "<resource name>"
    policy     = "<policy_id>"
    scanners   = ["<scanner_id>"]
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `asset` (Attributes) An asset (see [below for nested schema](#nestedatt--asset))

<a id="nestedatt--asset"></a>
### Nested Schema for `asset`

Required:

- `collection` (String) The collection of the resource.
- `provider` (String) The provider of the resource.
- `scanners` (List of String) List of scanners for the asset.

Optional:

- `policy` (String) The policy for the asset. 
 This field is different from the `assigned_policy` as terraform behaviour for optional and computed field is not detecting the removal of the policy.
- `resource` (String) The name of the resource.

Read-Only:

- `assigned_policy` (String) The policy assigned to the asset. 
 This might differ from the policy field as a resource might not be allow to change policy.
- `id` (String) The ID of the resource. 
 The ID is determined based on the provider collection and resource.
