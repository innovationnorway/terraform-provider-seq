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
