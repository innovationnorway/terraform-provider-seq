package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccResourceAPIKey_Basic(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckAPIKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceAPIKeyBasic("test", "Ingest"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("seq_api_key.test", "title", "test"),
					resource.TestCheckResourceAttr("seq_api_key.test", "assigned_permissions.0", "Ingest"),
					resource.TestCheckResourceAttrSet("seq_api_key.test", "is_default"),
					resource.TestCheckResourceAttrSet("seq_api_key.test", "token_prefix"),
				),
			},
			{
				// test update
				Config: testAccResourceAPIKeyBasic("test-update", "Read"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("seq_api_key.test", "title", "test-update"),
					resource.TestCheckResourceAttr("seq_api_key.test", "assigned_permissions.0", "Read"),
					resource.TestCheckResourceAttrSet("seq_api_key.test", "is_default"),
					resource.TestCheckResourceAttrSet("seq_api_key.test", "token_prefix"),
				),
			},
		},
	})
}

func TestAccResourceAPIKey_Token(t *testing.T) {
	token := acctest.RandString(20)
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckAPIKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceAPIKeyToken(token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("seq_api_key.test", "title", "test"),
					resource.TestCheckResourceAttr("seq_api_key.test", "token", token),
					resource.TestCheckResourceAttr("seq_api_key.test", "assigned_permissions.0", "Ingest"),
					resource.TestCheckResourceAttrSet("seq_api_key.test", "is_default"),
					resource.TestCheckResourceAttr("seq_api_key.test", "token_prefix", token[0:4]),
				),
			},
		},
	})
}

func TestAccResourceAPIKey_AssignedPermissions(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckAPIKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceAPIKeyAssignedPermissions,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("seq_api_key.test", "title", "test"),
					resource.TestCheckResourceAttr("seq_api_key.test", "assigned_permissions.0", "Ingest"),
					resource.TestCheckResourceAttr("seq_api_key.test", "assigned_permissions.1", "Read"),
					resource.TestCheckResourceAttr("seq_api_key.test", "assigned_permissions.2", "Setup"),
					resource.TestCheckResourceAttr("seq_api_key.test", "assigned_permissions.3", "Write"),
					resource.TestCheckResourceAttrSet("seq_api_key.test", "is_default"),
					resource.TestCheckResourceAttrSet("seq_api_key.test", "token_prefix"),
				),
			},
		},
	})
}

func testAccCheckAPIKeyDestroy(s *terraform.State) error {
	// TODO: add CheckDestroy
	return nil
}

func testAccResourceAPIKeyBasic(title string, permission string) string {
	return fmt.Sprintf(`
resource "seq_api_key" "test" {
  title = "%s"
  assigned_permissions = [
	"%s",
  ]
}
`, title, permission)
}

func testAccResourceAPIKeyToken(token string) string {
	return fmt.Sprintf(`
resource "seq_api_key" "test" {
  title = "test"
  token = "%s"
  assigned_permissions = [
	"Ingest",
  ]
}
`, token)
}

const testAccResourceAPIKeyAssignedPermissions = `
resource "seq_api_key" "test" {
  title = "test"
  assigned_permissions = [
	"Ingest",
	"Read",
	"Setup",
	"Write",
  ]
}
`
