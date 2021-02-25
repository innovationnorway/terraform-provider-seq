package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccResourceLicense_Basic(t *testing.T) {
	license := os.Getenv("SEQ_LICENSE")
	if license == "" {
		t.Skip(`Skipping test because "SEQ_LICENSE" is not set`)
	}
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckLicenseDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceLicenseBasic(license),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("seq_license.test", "license_text", license),
					resource.TestCheckResourceAttr("seq_license.test", "is_valid", "true"),
					resource.TestCheckResourceAttrSet("seq_license.test", "status_description"),
					resource.TestCheckResourceAttrSet("seq_license.test", "automatically_refresh"),
					resource.TestCheckResourceAttrSet("seq_license.test", "can_renew_online_now"),
					resource.TestCheckResourceAttrSet("seq_license.test", "is_single_user"),
					resource.TestCheckResourceAttrSet("seq_license.test", "is_warning"),
				),
			},
		},
	})
}

func testAccCheckLicenseDestroy(s *terraform.State) error {
	// TODO: add CheckDestroy
	return nil
}

func testAccResourceLicenseBasic(licenseText string) string {
	return fmt.Sprintf(`
resource "seq_license" "test" {
  license_text = "%s"
}
`, licenseText)
}
