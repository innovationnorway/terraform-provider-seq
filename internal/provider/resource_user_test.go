package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccResourceUser_Basic(t *testing.T) {
	if os.Getenv("SEQ_LICENSE") == "" {
		t.Skip(`Skipping test because "SEQ_LICENSE" is not set`)
	}
	username1 := acctest.RandStringFromCharSet(8, "abcdefghijklmnopqrstuvwxyz")
	username2 := acctest.RandStringFromCharSet(8, "abcdefghijklmnopqrstuvwxyz")
	password := acctest.RandString(20)
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceUserBasic(username1, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("seq_user.test", "username", username1),
					resource.TestCheckResourceAttr("seq_user.test", "display_name", "Test"),
					resource.TestCheckResourceAttr("seq_user.test", "email_address", "user@example.com"),
					resource.TestCheckResourceAttr("seq_user.test", "role_ids.0", "role-ro"),
				),
			},
			{
				// test update
				Config: testAccResourceUserBasic(username2, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("seq_user.test", "username", username2),
					resource.TestCheckResourceAttr("seq_user.test", "display_name", "Test"),
					resource.TestCheckResourceAttr("seq_user.test", "email_address", "user@example.com"),
					resource.TestCheckResourceAttr("seq_user.test", "role_ids.0", "role-ro"),
				),
			},
		},
	})
}

func testAccCheckUserDestroy(s *terraform.State) error {
	// TODO: add CheckDestroy
	return nil
}

func testAccResourceUserBasic(username, password string) string {
	return fmt.Sprintf(`
resource "seq_user" "test" {
  username     = "%s"
  password     = "%s"
  display_name = "Test"
  email_address = "user@example.com"
  role_ids = [
    "role-ro",
  ]
}
`, username, password)
}
