package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/innovationnorway/go-seq"
)

func resourceUser() *schema.Resource {
	return &schema.Resource{
		Description: "Use this resource to create a user on the Seq server.",

		CreateContext: resourceUserCreate,
		ReadContext:   resourceUserRead,
		UpdateContext: resourceUserUpdate,
		DeleteContext: resourceUserDelete,

		Schema: map[string]*schema.Schema{
			"username": {
				Description:      "The username that uniquely identifies the user.",
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"password": {
				Description:      "The password for the user.",
				Type:             schema.TypeString,
				Optional:         true,
				Sensitive:        true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"display_name": {
				Description: "An optional display name to aid in identifying the user.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"email_address": {
				Description: "The user's email address. This will be used to show a Gravatar for the user in some situations.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"role_ids": {
				Description: "The ids of one or more roles that grant permissions to the user. Possible values are `role-administrator` (Administrator), `role-ro` (User, read-only), `role-rw` (User, read/write) and `role-user` (User, read/write/ingest)`.",
				Type:        schema.TypeList,
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"must_change_password": {
				Description: "If `true`, the user will be unable to log in without first changing their password. Recommended when administratively assigning a password for the user.",
				Type:        schema.TypeBool,
				Optional:    true,
			},
		},
	}
}

func resourceUserCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	user := seq.User{
		Username: d.Get("username").(string),
	}

	if v, ok := d.GetOk("password"); ok {
		user.NewPassword = seq.PtrString(v.(string))
	}

	if v, ok := d.GetOk("display_name"); ok {
		user.DisplayName = seq.PtrString(v.(string))
	}

	if v, ok := d.GetOk("email_address"); ok {
		user.EmailAddress = seq.PtrString(v.(string))
	}

	if v, ok := d.GetOk("role_ids"); ok {
		var roles []string
		for _, r := range v.([]interface{}) {
			roles = append(roles, r.(string))
		}
		user.RoleIds = &roles
	}

	if v, ok := d.GetOk("must_change_password"); ok {
		user.MustChangePassword = seq.PtrBool(v.(bool))
	}

	r, resp, err := client.UsersApi.AddUser(auth).User(user).Execute()
	if err != nil {
		return diag.Errorf("error creating user (Username: %s): %s: %s", user.GetUsername(), err, resp.Body)
	}

	d.SetId(r.GetId())

	return resourceUserRead(ctx, d, meta)
}

func resourceUserRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	r, resp, err := client.UsersApi.GetUser(auth, d.Id()).Execute()
	if err != nil {
		return diag.Errorf("error getting user (ID: %s): %s: %s", d.Id(), err, resp.Body)
	}

	d.Set("username", r.GetUsername())
	d.Set("display_name", r.GetDisplayName())
	d.Set("email_address", r.GetEmailAddress())
	d.Set("role_ids", r.GetRoleIds())
	d.Set("must_change_password", r.GetMustChangePassword())

	return nil
}

func resourceUserUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
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

	if v, ok := d.GetOk("role_ids"); ok {
		var roles []string
		for _, r := range v.([]interface{}) {
			roles = append(roles, r.(string))
		}
		user.RoleIds = &roles
	}

	_, resp, err := client.UsersApi.UpdateUser(auth, d.Id()).User(user).Execute()
	if err != nil {
		return diag.Errorf("error updating user (ID: %s): %s: %s", d.Id(), err, resp.Body)
	}

	return resourceUserRead(ctx, d, meta)
}

func resourceUserDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	_, err := client.UsersApi.DeleteUser(auth, d.Id()).Execute()
	if err != nil {
		return diag.Errorf("error deleting user (ID: %s): %s", d.Id(), err)
	}

	return nil
}
