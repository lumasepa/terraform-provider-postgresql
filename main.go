package main

import (
	"github.com/hashicorp/terraform/plugin"
	"github.com/lumasepa/terraform-provider-postgresql/postgresql"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: postgresql.Provider})
}
