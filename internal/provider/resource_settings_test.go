package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccResourceSettings_Basic(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckSettingDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceSettingsBasic,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("seq_settings.test", "require_api_key_for_writing_events", "true"),
					resource.TestCheckResourceAttr("seq_settings.test", "check_for_updates", "true"),
					resource.TestCheckResourceAttr("seq_settings.test", "instance_title", "test"),
					resource.TestCheckResourceAttr("seq_settings.test", "minimum_password_length", "7"),
					resource.TestCheckResourceAttr("seq_settings.test", "backups_to_keep", "10"),
				),
			},
		},
	})
}

func TestAccResourceSettings_InstanceTitle(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckSettingDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceSettingsInstanceTitle("foo"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("seq_settings.test", "instance_title", "foo"),
				),
			},
			{
				// test update
				Config: testAccResourceSettingsInstanceTitle("bar"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("seq_settings.test", "instance_title", "bar"),
				),
			},
		},
	})
}

func TestAccResourceSettings_AzureAD(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckSettingDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceSettingsAzureAD,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("seq_settings.test", "authentication_provider", "Azure Active Directory"),
					resource.TestCheckResourceAttr("seq_settings.test", "azuread_client_id", "5601721f-555b-45d9-a9c7-5cd2c60a7148"),
					resource.TestCheckResourceAttr("seq_settings.test", "azuread_tenant_id", "e7d03e04-2ccf-493c-9c89-83a395e96260"),
					resource.TestCheckResourceAttr("seq_settings.test", "is_authentication_enabled", "true"),
				),
			},
		},
	})
}

func testAccCheckSettingDestroy(s *terraform.State) error {
	// TODO: add CheckDestroy
	return nil
}

const testAccResourceSettingsBasic = `
resource "seq_settings" "test" {
  require_api_key_for_writing_events = true
  check_for_updates                  = true
  instance_title                     = "test"
  minimum_password_length            = 7
  backups_to_keep                    = 10
}
`

func testAccResourceSettingsInstanceTitle(instanceTitle string) string {
	return fmt.Sprintf(`
resource "seq_settings" "test" {
  instance_title = "%s"
}
`, instanceTitle)
}

//lintignore:AT004
const testAccResourceSettingsAzureAD = `
provider "seq" {
  api_key = "Gaz48ULsNjlzfvfQMTln"
}

resource "seq_api_key" "test" {
  title = "test"
  token = "Gaz48ULsNjlzfvfQMTln"
  assigned_permissions = [
    "Read",
    "Write",
    "Setup",
  ]
}

resource "seq_settings" "test" {
  authentication_provider   = "Azure Active Directory"
  azuread_client_id         = "5601721f-555b-45d9-a9c7-5cd2c60a7148"
  azuread_tenant_id         = "e7d03e04-2ccf-493c-9c89-83a395e96260"
  azuread_client_key        = "7HKzxCKPAGdR4Zzsbu5jKEzD9PU7tpGv"
  is_authentication_enabled = true
  depends_on = [
    seq_api_key.test,
  ]
}
`
