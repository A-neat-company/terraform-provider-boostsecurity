terraform {
  required_providers {
    boostsecurity = {
      source = "Dyc0de/test/boostsecurity"
    }
  }
  required_version = ">= 1.1.0"
}

provider "boostsecurity" {
  host     = "https://api.dev.boostsec.io/asset-management/graphql"
  token    = "<token>"
}


# resource "boostsecurity_asset_coverage" "a-free-org" {
#   asset = {
#       provider = "GitHub"
#       collection = "a-free-org"
#       policy = "boostsecurityio:actions-by-labels"
#       scanners = ["cicd_github_org_analyzer", "sci_github_org_analyzer"]
#   }
# }
#
# resource "boostsecurity_fortify" "railsgoat" {
#   asset = {
#     provider = "GitLab"
#     collection = "boostsecurityio/dylan/le-subgroupe-de-la-mort"
#     resource = "railsgoat"
# #     policy = "e5713990-d89c-4ab7-8c02-c0b1d070331c"
# #     policy = "boostsecurityio:actions-by-labels"
#     scanners = ["boostsecurityio/brakeman"]
#   }
# }

#
# output "railsgoat" {
#   value = boostsecurity_asset_coverage.railsgoat
# }


# output "a-free-org" {
#   value = boostsecurity_asset_coverage.a-free-org
# }