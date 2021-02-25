package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccResourceAdminUser_Basic(t *testing.T) {
	password := os.Getenv("SEQ_ADMIN_PASSWORD")
	if password == "" {
		t.Skip(`Skipping test because "SEQ_ADMIN_PASSWORD" is not set`)
	}
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceAdminUserBasic("admin", password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("seq_admin_user.test", "username", "admin"),
					resource.TestCheckResourceAttr("seq_admin_user.test", "display_name", "Test"),
					resource.TestCheckResourceAttr("seq_admin_user.test", "email_address", "admin@example.com"),
				),
			},
		},
	})
}

func testAccCheckAdminUserDestroy(s *terraform.State) error {
	// TODO: add CheckDestroy
	return nil
}

func testAccResourceAdminUserBasic(username, password string) string {
	return fmt.Sprintf(`
resource "seq_admin_user" "test" {
  username     = "%s"
  password     = "%s"
  display_name = "Test"
  email_address = "admin@example.com"
}
`, username, password)
}
