package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/innovationnorway/go-seq"
)

func resourceAdminUser() *schema.Resource {
	return &schema.Resource{
		Description: "Use this resource to manage the admin user on the Seq server.",

		CreateContext: resourceAdminUserCreate,
		ReadContext:   resourceAdminUserRead,
		UpdateContext: resourceAdminUserUpdate,
		DeleteContext: resourceAdminUserDelete,

		Schema: map[string]*schema.Schema{
			"username": {
				Description:      "The username that uniquely identifies the admin user.",
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"password": {
				Description:      "The password for the admin user.",
				Type:             schema.TypeString,
				Required:         true,
				Sensitive:        true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"display_name": {
				Description: "An optional display name to aid in identifying the admin user.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"email_address": {
				Description: "The admin user's email address.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"must_change_password": {
				Description: "If `true`, the admin user will be unable to log in without first changing their password.",
				Type:        schema.TypeBool,
				Optional:    true,
			},
		},
	}
}

func resourceAdminUserCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	id := "user-admin"

	user := seq.User{
		Id:          seq.PtrString(id),
		Username:    d.Get("username").(string),
		NewPassword: seq.PtrString(d.Get("password").(string)),
	}

	if v, ok := d.GetOk("display_name"); ok {
		user.DisplayName = seq.PtrString(v.(string))
	}

	if v, ok := d.GetOk("email_address"); ok {
		user.EmailAddress = seq.PtrString(v.(string))
	}

	if v, ok := d.GetOk("must_change_password"); ok {
		user.MustChangePassword = seq.PtrBool(v.(bool))
	}

	r, resp, err := client.UsersApi.UpdateUser(auth, id).User(user).Execute()
	if err != nil {
		return diag.Errorf("error creating admin user: %s: %s", err, resp.Body)
	}

	d.SetId(r.GetId())

	return resourceAdminUserRead(ctx, d, meta)
}

func resourceAdminUserRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	r, resp, err := client.UsersApi.GetUser(auth, d.Id()).Execute()
	if err != nil {
		return diag.Errorf("error getting admin user: %s: %s", err, resp.Body)
	}

	d.Set("username", r.GetUsername())
	d.Set("display_name", r.GetDisplayName())
	d.Set("email_address", r.GetEmailAddress())
	d.Set("must_change_password", r.GetMustChangePassword())

	return nil
}

func resourceAdminUserUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	user := seq.User{
		Id:       seq.PtrString(d.Id()),
		Username: d.Get("username").(string),
	}

	if d.HasChange("password") {
		if v, ok := d.GetOk("password"); ok {
			user.NewPassword = seq.PtrString(v.(string))
		}
	}

	if d.HasChange("must_change_password") {
		if v, ok := d.GetOk("must_change_password"); ok {
			user.MustChangePassword = seq.PtrBool(v.(bool))
		}
	}

	if v, ok := d.GetOk("display_name"); ok {
		user.DisplayName = seq.PtrString(v.(string))
	}

	if v, ok := d.GetOk("email_address"); ok {
		user.EmailAddress = seq.PtrString(v.(string))
	}

	_, resp, err := client.UsersApi.UpdateUser(auth, d.Id()).User(user).Execute()
	if err != nil {
		return diag.Errorf("error creating admin user: %s: %s", err, resp.Body)
	}

	return resourceAdminUserRead(ctx, d, meta)
}

func resourceAdminUserDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// client := meta.(*apiClient).client
	// auth := meta.(*apiClient).auth

	// TODO: implement Delete

	return nil
}
