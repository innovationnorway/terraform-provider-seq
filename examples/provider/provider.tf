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
