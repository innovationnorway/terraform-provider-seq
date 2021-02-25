package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/innovationnorway/go-seq"
)

func resourceLicense() *schema.Resource {
	return &schema.Resource{
		Description: "Use this resource to update the Seq license.",

		CreateContext: resourceLicenseCreateUpdate,
		ReadContext:   resourceLicenseRead,
		UpdateContext: resourceLicenseCreateUpdate,
		DeleteContext: resourceLicenseDelete,

		Schema: map[string]*schema.Schema{
			"license_text": {
				Description:      "The cryptographically-signed certificate that describes the license.",
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"status_description": {
				Description: "Information about the status of the license.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"licensed_users": {
				Description: "The number of users licensed to access the Seq server, or `null` if the license has no user limit.",
				Type:        schema.TypeInt,
				Computed:    true,
			},
			"subscription_id": {
				Description: "If the license is a subscription, the subscription id.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"automatically_refresh": {
				Description: "If the license is for a subscription, automatically check datalust.co and update the license when the subscription is renewed or tier changed.",
				Type:        schema.TypeBool,
				Computed:    true,
			},
			"can_renew_online_now": {
				Description: "If `true`, the license can be renewed online.",
				Type:        schema.TypeBool,
				Computed:    true,
			},
			"is_valid": {
				Description: "Whether or not the license is valid for the server.",
				Type:        schema.TypeBool,
				Computed:    true,
			},
			"is_single_user": {
				Description: "If `true`, the server is using the default license which allows a single person to access the Seq server.",
				Type:        schema.TypeBool,
				Computed:    true,
			},
			"is_warning": {
				Description: "If `true`, see `status_description` for important information.",
				Type:        schema.TypeBool,
				Computed:    true,
			},
		},
	}
}

func resourceLicenseCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	id := "license-server"

	license := seq.License{
		Id:          seq.PtrString(id),
		LicenseText: d.Get("license_text").(string),
	}

	r, resp, err := client.LicensesApi.UpdateLicense(auth, id).License(license).Execute()
	if err != nil {
		return diag.Errorf("error updating license (ID %s): %s: %s", id, err, resp.Body)
	}

	d.SetId(r.GetId())

	return resourceLicenseRead(ctx, d, meta)
}

func resourceLicenseRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	r, resp, err := client.LicensesApi.GetLicense(auth, d.Id()).Execute()
	if err != nil {
		return diag.Errorf("error getting license (ID: %s): %s: %s", d.Id(), err, resp.Body)
	}

	d.Set("license_text", r.GetLicenseText())
	d.Set("status_description", r.GetStatusDescription())
	d.Set("licensed_users", r.GetLicensedUsers())
	d.Set("subscription_id", r.GetSubscriptionId())
	d.Set("automatically_refresh", r.GetAutomaticallyRefresh())
	d.Set("can_renew_online_now", r.GetCanRenewOnlineNow())
	d.Set("is_valid", r.GetIsValid())
	d.Set("is_single_user", r.GetIsSingleUser())
	d.Set("is_warning", r.GetIsWarning())

	return nil
}

func resourceLicenseDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	resp, err := client.LicensesApi.DowngradeLicense(auth).Execute()
	if err != nil {
		return diag.Errorf("error downgrading license: %s: %s", err, resp.Body)
	}

	return nil
}
