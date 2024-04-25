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