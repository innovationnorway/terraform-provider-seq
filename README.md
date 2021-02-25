![](https://blog.datalust.co/content/images/2018/09/Seq-380px-1.png)

# Terraform Provider Seq

Available in the [Terraform Registry](https://registry.terraform.io/providers/innovationnorway/seq/latest).

## Requirements

-	[Terraform](https://www.terraform.io/downloads.html) >= 0.13.x
-	[Go](https://golang.org/doc/install) >= 1.15

## Building The Provider

1. Clone the repository
1. Enter the repository directory
1. Build the provider using the Go `install` command: 
```sh
$ go install
```

## Adding Dependencies

This provider uses [Go modules](https://github.com/golang/go/wiki/Modules).
Please see the Go documentation for the most up to date information about using Go modules.

To add a new dependency `github.com/author/dependency` to your Terraform provider:

```
go get github.com/author/dependency
go mod tidy
```

Then commit the changes to `go.mod` and `go.sum`.

## Using the provider

```terraform
variable "server_url" {
  type = string
}

variable "api_key" {
  type      = string
  sensitive = true
}

provider "seq" {
  server_url = var.server_url
  api_key    = var.api_key
}

resource "seq_api_token" "example" {
  title = "example"
  token = "jdJfrXPcEuw72Jv260nz"
  assigned_permissions = [
    "Ingest",
  ]
}

resource "seq_settings" "example" {
  require_api_key_for_writing_events = true
}
```

## Developing the Provider

If you wish to work on the provider, you'll first need [Go](http://www.golang.org) installed on your machine (see [Requirements](#requirements) above).

To compile the provider, run `go install`. This will build the provider and put the provider binary in the `$GOPATH/bin` directory.

To generate or update documentation, run `go generate`.

In order to run the full suite of Acceptance tests, run `make testacc`.

*Note:* Acceptance tests create real resources, and often cost money to run.

```sh
$ make testacc
```
