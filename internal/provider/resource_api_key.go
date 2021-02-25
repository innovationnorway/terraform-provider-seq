package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/innovationnorway/go-seq"
)

func resourceAPIKey() *schema.Resource {
	return &schema.Resource{
		Description: "Use this resource to create and manage API keys.",

		CreateContext: resourceAPIKeyCreate,
		ReadContext:   resourceAPIKeyRead,
		UpdateContext: resourceAPIKeyUpdate,
		DeleteContext: resourceAPIKeyDelete,

		Schema: map[string]*schema.Schema{
			"title": {
				Description:      "A title for the API key.",
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"token": {
				Description:      "A pre-allocated API key token; by default, a new token will be generated.",
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				Sensitive:        true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"owner_id": {
				Description: "The id of the user for whom this is a personal API key.",
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
			},
			"assigned_permissions": {
				Description: "List of permissions assigned to the API key. Possible values are `Ingest`, `Read`, `Setup` and `Write`.",
				Type:        schema.TypeList,
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"is_default": {
				Description: "If `true`, the key is the built-in (tokenless) API key representing unauthenticated HTTP ingestion.",
				Type:        schema.TypeBool,
				Optional:    true,
			},
			"token_prefix": {
				Description: "A few characters from the start of the `token` stored as plain text, to aid in identifying tokens.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

func resourceAPIKeyCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	apiKey := seq.ApiKey{
		Title: d.Get("title").(string),
	}

	if v, ok := d.GetOk("token"); ok {
		apiKey.Token = seq.PtrString(v.(string))
	}

	if v, ok := d.GetOk("owner_id"); ok {
		apiKey.OwnerId = seq.PtrString(v.(string))
	}

	if v, ok := d.GetOk("assigned_permissions"); ok {
		var perms []string
		for _, p := range v.([]interface{}) {
			perms = append(perms, p.(string))
		}
		apiKey.AssignedPermissions = &perms
	}

	r, resp, err := client.ApikeysApi.AddApiKey(auth).ApiKey(apiKey).Execute()
	if err != nil {
		return diag.Errorf("error creating API key: %s: %s", err, resp.Body)
	}

	d.SetId(r.GetId())

	return resourceAPIKeyRead(ctx, d, meta)
}

func resourceAPIKeyRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	r, resp, err := client.ApikeysApi.GetApiKey(auth, d.Id()).Execute()
	if err != nil {
		return diag.Errorf("error getting API key (ID: %s): %s: %s", d.Id(), err, resp.Body)
	}

	d.Set("title", r.GetTitle())
	d.Set("assigned_permissions", r.GetAssignedPermissions())
	d.Set("owner_id", r.GetOwnerId())
	d.Set("is_default", r.GetIsDefault())
	d.Set("token_prefix", r.GetTokenPrefix())

	return nil
}

func resourceAPIKeyUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	apiKey := seq.ApiKey{
		Id:    seq.PtrString(d.Id()),
		Title: d.Get("title").(string),
	}

	if v, ok := d.GetOk("owner_id"); ok {
		apiKey.OwnerId = seq.PtrString(v.(string))
	}

	if v, ok := d.GetOk("assigned_permissions"); ok {
		var perms []string
		for _, p := range v.([]interface{}) {
			perms = append(perms, p.(string))
		}
		apiKey.AssignedPermissions = &perms
	}

	_, resp, err := client.ApikeysApi.UpdateApiKey(auth, d.Id()).ApiKey(apiKey).Execute()
	if err != nil {
		return diag.Errorf("error updating API key: %s: %s", err, resp.Body)
	}

	return resourceAPIKeyRead(ctx, d, meta)
}

func resourceAPIKeyDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	resp, err := client.ApikeysApi.DeleteApiKey(auth, d.Id()).Execute()
	if err != nil {
		return diag.Errorf("error deleting API key (ID: %s): %s: %s", d.Id(), err, resp.Body)
	}

	return nil
}
