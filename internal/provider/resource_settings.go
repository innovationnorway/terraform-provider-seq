package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/innovationnorway/go-seq"
)

func resourceSettings() *schema.Resource {
	return &schema.Resource{
		Description: "Use this resource to manage system settings.",

		CreateContext: resourceSettingsCreate,
		ReadContext:   resourceSettingsRead,
		UpdateContext: resourceSettingsUpdate,
		DeleteContext: resourceSettingsDelete,

		Schema: map[string]*schema.Schema{
			"authentication_provider": {
				Description: "The authentication provider to use. Allowed values are `Active Directory`, `Azure Active Directory` and `OpenID Connect`.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"automatically_provision_authenticated_users": {
				Description: "If `true`, users authenticated with the configured authentication provider be automatically granted default user access to Seq.",
				Type:        schema.TypeBool,
				Optional:    true,
			},
			"automatic_access_ad_group": {
				Description: "The name of an Active Directory group within which users will be automatically be granted user access to Seq.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"is_authentication_enabled": {
				Description: "If `true`, the server has authentication enabled.",
				Type:        schema.TypeBool,
				Optional:    true,
			},
			"require_api_key_for_writing_events": {
				Description: "If `true`, ingestion requests incoming via HTTP must be authenticated using an API key or logged-in user session. Only effective when `is_authentication_enabled` is `true`.",
				Type:        schema.TypeBool,
				Optional:    true,
			},
			"check_for_updates": {
				Description: "If `true`, Seq will periodically check for new Seq versions.",
				Type:        schema.TypeBool,
				Optional:    true,
			},
			"check_for_package_updates": {
				Description: "If `true`, Seq will periodically check configured NuGet feed for updated versions of installed app packages.",
				Type:        schema.TypeBool,
				Optional:    true,
			},
			"raw_payload_maximum_content_length": {
				Description: "The maximum size, in HTTP request content bytes, beyond which ingestion requests will be rejected.",
				Type:        schema.TypeInt,
				Optional:    true,
			},
			"raw_event_maximum_content_length": {
				Description: "The maximum size, in bytes of UTF-8-encoded JSON, beyond which individual events will be rejected.",
				Type:        schema.TypeInt,
				Optional:    true,
			},
			"minimum_free_storage_space": {
				Description: "The minimum storage space, in bytes, on the disk containing log events, before Seq will stop accepting new events.",
				Type:        schema.TypeInt,
				Optional:    true,
			},
			"theme_styles": {
				Description: "A snippet of CSS that will be included in the front-end's user interface styles.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"azuread_authority": {
				Description: "The AAD authority. The default is `login.windows.net`.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"azuread_tenant_id": {
				Description: "The Azure Active Directory tenant id.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"azuread_client_id": {
				Description: "The Azure Active Directory client id.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"azuread_client_key": {
				Description: "The Azure Active Directory client key.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"backup_location": {
				Description: "Server-local filesystem location where automatic backups are stored.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"backup_utc_time_of_day": {
				Description: "",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"backups_to_keep": {
				Description: "The UTC time of day to record new backups.",
				Type:        schema.TypeInt,
				Optional:    true,
			},
			"new_user_role_ids": {
				Description: "A comma-separated list of role ids that will be assigned to new users by default.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"new_user_show_signal_ids": {
				Description: "A comma-separated list of (shared) signal ids that will be included in any new user's personal default workspace.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"new_user_show_query_ids": {
				Description: "A comma-separated list of (shared) SQL query ids that will be included in any new user's personal default workspace.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"new_user_show_dashboard_ids": {
				Description: "A comma-separated list of (shared) dashboard ids that will be included in any new user's personal default workspace.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"instance_title": {
				Description: "A friendly, public, human-readable title identifying this particular Seq instance.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"minimum_password_length": {
				Description: "",
				Type:        schema.TypeInt,
				Optional:    true,
			},
			"password_required_character_classes": {
				Description: "",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"openid_connect_authority": {
				Description: "If using OpenID Connect authentication, the URL of the authorization endpoint.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"openid_connect_client_id": {
				Description: "If using OpenID Connect, the client id assigned to Seq in the provider.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"openid_connect_client_secret": {
				Description: "If using OpenID Connect, the client secret assigned to Seq in the provider.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"openid_connect_scopes": {
				Description: "If using OpenID Connect, the scopes Seq will request when authorizing the client, as a comma-separated list. For example, `openid, profile, email`.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"openid_connect_end_session_redirect_uri": {
				Description: "",
				Type:        schema.TypeString,
				Optional:    true,
			},
		},
	}
}

func resourceSettingsCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	var ids []string

	if v, ok := d.GetOk("automatically_provision_authenticated_users"); ok {
		id := "setting-automaticallyprovisionauthenticatedusers"
		name := "automaticallyprovisionauthenticatedusers"
		setting := seq.AutomaticallyProvisionAuthenticatedUsersAsSetting(
			&seq.AutomaticallyProvisionAuthenticatedUsers{
				Id:    id,
				Name:  name,
				Value: seq.PtrBool(v.(bool)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("automatic_access_ad_group"); ok {
		id := "setting-automaticaccessadgroup"
		name := "setting-automaticaccessadgroup"
		setting := seq.AutomaticAccessADGroupAsSetting(
			&seq.AutomaticAccessADGroup{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("require_api_key_for_writing_events"); ok {
		id := "setting-requireapikeyforwritingevents"
		name := "requireapikeyforwritingevents"
		setting := seq.RequireApiKeyForWritingEventsAsSetting(
			&seq.RequireApiKeyForWritingEvents{
				Id:    id,
				Name:  name,
				Value: seq.PtrBool(v.(bool)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("check_for_updates"); ok {
		id := "setting-checkforupdates"
		name := "checkforupdates"
		setting := seq.CheckForUpdatesAsSetting(
			&seq.CheckForUpdates{
				Id:    id,
				Name:  name,
				Value: seq.PtrBool(v.(bool)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("check_for_package_updates"); ok {
		id := "setting-checkforpackageupdates"
		name := "checkforpackageupdates"
		setting := seq.CheckForPackageUpdatesAsSetting(
			&seq.CheckForPackageUpdates{
				Id:    id,
				Name:  name,
				Value: seq.PtrBool(v.(bool)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("raw_payload_maximum_content_length"); ok {
		id := "setting-rawpayloadmaximumcontentlength"
		name := "rawpayloadmaximumcontentlength"
		setting := seq.RawPayloadMaximumContentLengthAsSetting(
			&seq.RawPayloadMaximumContentLength{
				Id:    id,
				Name:  name,
				Value: seq.PtrInt32(int32(v.(int))),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("raw_event_maximum_content_length"); ok {
		id := "setting-raweventmaximumcontentlength"
		name := "raweventmaximumcontentlength"
		setting := seq.RawEventMaximumContentLengthAsSetting(
			&seq.RawEventMaximumContentLength{
				Id:    id,
				Name:  name,
				Value: seq.PtrInt32(int32(v.(int))),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("minimum_free_storage_space"); ok {
		id := "setting-minimumfreestoragespace"
		name := "minimumfreestoragespace"
		setting := seq.MinimumFreeStorageSpaceAsSetting(
			&seq.MinimumFreeStorageSpace{
				Id:    id,
				Name:  name,
				Value: seq.PtrInt32(int32(v.(int))),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("theme_styles"); ok {
		id := "setting-themestyles"
		name := "themestyles"
		setting := seq.ThemeStylesAsSetting(
			&seq.ThemeStyles{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("azuread_authority"); ok {
		id := "setting-azureadauthority"
		name := "azureadauthority"
		setting := seq.AzureADAuthorityAsSetting(
			&seq.AzureADAuthority{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("azuread_tenant_id"); ok {
		id := "setting-azureadtenantid"
		name := "azureadtenantid"
		setting := seq.AzureADTenantIdAsSetting(
			&seq.AzureADTenantId{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("azuread_client_id"); ok {
		id := "setting-azureadclientid"
		name := "azureadclientid"
		setting := seq.AzureADClientIdAsSetting(
			&seq.AzureADClientId{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("azuread_client_key"); ok {
		id := "setting-azureadclientkey"
		name := "azureadclientkey"
		setting := seq.AzureADClientKeyAsSetting(
			&seq.AzureADClientKey{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("backup_location"); ok {
		id := "setting-backuplocation"
		name := "backuplocation"
		setting := seq.BackupLocationAsSetting(
			&seq.BackupLocation{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("backup_utc_time_of_day"); ok {
		id := "setting-backuputctimeofday"
		name := "backuputctimeofday"
		setting := seq.BackupUtcTimeOfDayAsSetting(
			&seq.BackupUtcTimeOfDay{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("backups_to_keep"); ok {
		id := "setting-backupstokeep"
		name := "backupstokeep"
		setting := seq.BackupsToKeepAsSetting(
			&seq.BackupsToKeep{
				Id:    id,
				Name:  name,
				Value: seq.PtrInt32(int32(v.(int))),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("new_user_role_ids"); ok {
		id := "setting-newuserroleids"
		name := "newuserroleids"
		setting := seq.NewUserRoleIdsAsSetting(
			&seq.NewUserRoleIds{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("new_user_show_signal_ids"); ok {
		id := "setting-newusershowsignalids"
		name := "newusershowsignalids"
		setting := seq.NewUserShowSignalIdsAsSetting(
			&seq.NewUserShowSignalIds{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("new_user_show_query_ids"); ok {
		id := "setting-newusershowqueryids"
		name := "newusershowqueryids"
		setting := seq.NewUserShowQueryIdsAsSetting(
			&seq.NewUserShowQueryIds{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("new_user_show_dashboard_ids"); ok {
		id := "setting-newusershowdashboardids"
		name := "newusershowdashboardids"
		setting := seq.NewUserShowDashboardIdsAsSetting(
			&seq.NewUserShowDashboardIds{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("instance_title"); ok {
		id := "setting-instancetitle"
		name := "instancetitle"
		setting := seq.InstanceTitleAsSetting(
			&seq.InstanceTitle{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("minimum_password_length"); ok {
		id := "setting-minimumpasswordlength"
		name := "minimumpasswordlength"
		setting := seq.MinimumPasswordLengthAsSetting(
			&seq.MinimumPasswordLength{
				Id:    id,
				Name:  name,
				Value: seq.PtrInt32(int32(v.(int))),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("password_required_character_classes"); ok {
		id := "setting-passwordrequiredcharacterclasses"
		name := "passwordrequiredcharacterclasses"
		setting := seq.PasswordRequiredCharacterClassesAsSetting(
			&seq.PasswordRequiredCharacterClasses{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("openid_connect_authority"); ok {
		id := "setting-openidconnectauthority"
		name := "openidconnectauthority"
		setting := seq.OpenIdConnectAuthorityAsSetting(
			&seq.OpenIdConnectAuthority{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("openid_connect_client_id"); ok {
		id := "setting-openidconnectclientid"
		name := "openidconnectclientid"
		setting := seq.OpenIdConnectClientIdAsSetting(
			&seq.OpenIdConnectClientId{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("openid_connect_client_secret"); ok {
		id := "setting-openidconnectclientsecret"
		name := "openidconnectclientsecret"
		setting := seq.OpenIdConnectClientSecretAsSetting(
			&seq.OpenIdConnectClientSecret{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("openid_connect_scopes"); ok {
		id := "setting-openidconnectscopes"
		name := "openidconnectscopes"
		setting := seq.OpenIdConnectScopesAsSetting(
			&seq.OpenIdConnectScopes{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("openid_connect_end_session_redirect_uri"); ok {
		id := "setting-openidconnectendsessionredirecturi"
		name := "openidconnectendsessionredirecturi"
		setting := seq.OpenIdConnectEndSessionRedirectUriAsSetting(
			&seq.OpenIdConnectEndSessionRedirectUri{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("authentication_provider"); ok {
		id := "setting-authenticationprovider"
		name := "authenticationprovider"
		setting := seq.AuthenticationProviderAsSetting(
			&seq.AuthenticationProvider{
				Id:    id,
				Name:  name,
				Value: seq.PtrString(v.(string)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	if v, ok := d.GetOk("is_authentication_enabled"); ok {
		id := "setting-isauthenticationenabled"
		name := "isauthenticationenabled"
		setting := seq.IsAuthenticationEnabledAsSetting(
			&seq.IsAuthenticationEnabled{
				Id:    id,
				Name:  name,
				Value: seq.PtrBool(v.(bool)),
			},
		)
		_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
		if err != nil {
			return diag.Errorf("error creating setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		ids = append(ids, id)
	}

	d.SetId(fmt.Sprintf("%x", schema.HashString(fmt.Sprint(ids))))

	return resourceSettingsRead(ctx, d, meta)
}

func resourceSettingsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	if _, ok := d.GetOk("authentication_provider"); ok {
		id := "setting-authenticationprovider"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("authentication_provider", r.AuthenticationProvider.GetValue())
	}

	if _, ok := d.GetOk("automatically_provision_authenticated_users"); ok {
		id := "setting-automaticallyprovisionauthenticatedusers"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("automatically_provision_authenticated_users", r.AutomaticallyProvisionAuthenticatedUsers.GetValue())
	}

	if _, ok := d.GetOk("automatic_access_ad_group"); ok {
		id := "setting-automaticaccessadgroup"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("automatic_access_ad_group", r.AutomaticAccessADGroup.GetValue())
	}

	if _, ok := d.GetOk("is_authentication_enabled"); ok {
		id := "setting-isauthenticationenabled"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("is_authentication_enabled", r.IsAuthenticationEnabled.GetValue())
	}

	if _, ok := d.GetOk("require_api_key_for_writing_events"); ok {
		id := "setting-requireapikeyforwritingevents"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("require_api_key_for_writing_events", r.RequireApiKeyForWritingEvents.GetValue())
	}

	if _, ok := d.GetOk("check_for_updates"); ok {
		id := "setting-checkforupdates"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("check_for_updates", r.CheckForUpdates.GetValue())
	}

	if _, ok := d.GetOk("check_for_package_updates"); ok {
		id := "setting-checkforpackageupdates"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("check_for_package_updates", r.CheckForUpdates.GetValue())
	}

	if _, ok := d.GetOk("raw_payload_maximum_content_length"); ok {
		id := "setting-rawpayloadmaximumcontentlength"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("raw_payload_maximum_content_length", r.RawPayloadMaximumContentLength.GetValue())
	}

	if _, ok := d.GetOk("raw_event_maximum_content_length"); ok {
		id := "setting-raweventmaximumcontentlength"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("raw_event_maximum_content_length", r.RawEventMaximumContentLength.GetValue())
	}

	if _, ok := d.GetOk("minimum_free_storage_space"); ok {
		id := "setting-minimumfreestoragespace"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("minimum_free_storage_space", r.MinimumFreeStorageSpace.GetValue())
	}

	if _, ok := d.GetOk("theme_styles"); ok {
		id := "setting-themestyles"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("theme_styles", r.ThemeStyles.GetValue())
	}

	if _, ok := d.GetOk("azuread_authority"); ok {
		id := "setting-azureadauthority"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("azuread_authority", r.AzureADAuthority.GetValue())
	}

	if _, ok := d.GetOk("azuread_tenant_id"); ok {
		id := "setting-azureadtenantid"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("azuread_tenant_id", r.AzureADTenantId.GetValue())
	}

	if _, ok := d.GetOk("azuread_client_id"); ok {
		id := "setting-azureadclientid"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("azuread_client_id", r.AzureADClientId.GetValue())
	}

	if _, ok := d.GetOk("azuread_client_key"); ok {
		id := "setting-azureadclientkey"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("azuread_client_key", r.AzureADClientKey.GetValue())
	}

	if _, ok := d.GetOk("backup_location"); ok {
		id := "setting-backuplocation"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("backup_location", r.BackupLocation.GetValue())
	}

	if _, ok := d.GetOk("backup_utc_time_of_day"); ok {
		id := "setting-backuputctimeofday"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("backup_utc_time_of_day", r.BackupUtcTimeOfDay.GetValue())
	}

	if _, ok := d.GetOk("backups_to_keep"); ok {
		id := "setting-backupstokeep"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("backups_to_keep", r.BackupsToKeep.GetValue())
	}

	if _, ok := d.GetOk("new_user_role_ids"); ok {
		id := "setting-newuserroleids"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("new_user_role_ids", r.NewUserRoleIds.GetValue())
	}

	if _, ok := d.GetOk("new_user_show_signal_ids"); ok {
		id := "setting-newusershowsignalids"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("new_user_show_signal_ids", r.NewUserShowSignalIds.GetValue())
	}

	if _, ok := d.GetOk("new_user_show_query_ids"); ok {
		id := "setting-newusershowqueryids"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("new_user_show_query_ids", r.NewUserShowQueryIds.GetValue())
	}

	if _, ok := d.GetOk("new_user_show_dashboard_ids"); ok {
		id := "setting-newusershowdashboardids"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("new_user_show_dashboard_ids", r.NewUserShowDashboardIds.GetValue())
	}

	if _, ok := d.GetOk("instance_title"); ok {
		id := "setting-instancetitle"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("instance_title", r.InstanceTitle.GetValue())
	}

	if _, ok := d.GetOk("minimum_password_length"); ok {
		id := "setting-minimumpasswordlength"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("minimum_password_length", r.MinimumPasswordLength.GetValue())
	}

	if _, ok := d.GetOk("password_required_character_classes"); ok {
		id := "setting-passwordrequiredcharacterclasses"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("password_required_character_classes", r.PasswordRequiredCharacterClasses.GetValue())
	}

	if _, ok := d.GetOk("openid_connect_authority"); ok {
		id := "setting-openidconnectauthority"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("openid_connect_authority", r.OpenIdConnectAuthority.GetValue())
	}

	if _, ok := d.GetOk("openid_connect_client_id"); ok {
		id := "setting-openidconnectclientid"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("openid_connect_client_id", r.OpenIdConnectClientId.GetValue())
	}

	if _, ok := d.GetOk("openid_connect_client_secret"); ok {
		id := "setting-openidconnectclientsecret"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("openid_connect_client_secret", r.OpenIdConnectClientSecret.GetValue())
	}

	if _, ok := d.GetOk("openid_connect_scopes"); ok {
		id := "setting-openidconnectscopes"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("openid_connect_scopes", r.OpenIdConnectScopes.GetValue())
	}

	if _, ok := d.GetOk("openid_connect_end_session_redirect_uri"); ok {
		id := "setting-openidconnectendsessionredirecturi"
		r, resp, err := client.SettingsApi.GetSetting(auth, id).Execute()
		if err != nil {
			return diag.Errorf("error getting setting (ID: %s): %s: %s", id, err, resp.Body)
		}
		d.Set("openid_connect_end_session_redirect_uri", r.OpenIdConnectEndSessionRedirectUri.GetValue())
	}

	return nil
}

func resourceSettingsUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient).client
	auth := meta.(*apiClient).auth

	if d.HasChange("automatically_provision_authenticated_users") {
		if v, ok := d.GetOk("automatically_provision_authenticated_users"); ok {
			id := "setting-automaticallyprovisionauthenticatedusers"
			name := "automaticallyprovisionauthenticatedusers"
			setting := seq.AutomaticallyProvisionAuthenticatedUsersAsSetting(
				&seq.AutomaticallyProvisionAuthenticatedUsers{
					Id:    id,
					Name:  name,
					Value: seq.PtrBool(v.(bool)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("automatic_access_ad_group") {
		if v, ok := d.GetOk("automatic_access_ad_group"); ok {
			id := "setting-automaticaccessadgroup"
			name := "setting-automaticaccessadgroup"
			setting := seq.AutomaticAccessADGroupAsSetting(
				&seq.AutomaticAccessADGroup{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("require_api_key_for_writing_events") {
		if v, ok := d.GetOk("require_api_key_for_writing_events"); ok {
			id := "setting-requireapikeyforwritingevents"
			name := "requireapikeyforwritingevents"
			setting := seq.RequireApiKeyForWritingEventsAsSetting(
				&seq.RequireApiKeyForWritingEvents{
					Id:    id,
					Name:  name,
					Value: seq.PtrBool(v.(bool)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("check_for_updates") {
		if v, ok := d.GetOk("check_for_updates"); ok {
			id := "setting-checkforupdates"
			name := "checkforupdates"
			setting := seq.CheckForUpdatesAsSetting(
				&seq.CheckForUpdates{
					Id:    id,
					Name:  name,
					Value: seq.PtrBool(v.(bool)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("check_for_package_updates") {
		if v, ok := d.GetOk("check_for_package_updates"); ok {
			id := "setting-checkforpackageupdates"
			name := "checkforpackageupdates"
			setting := seq.CheckForPackageUpdatesAsSetting(
				&seq.CheckForPackageUpdates{
					Id:    id,
					Name:  name,
					Value: seq.PtrBool(v.(bool)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("raw_payload_maximum_content_length") {
		if v, ok := d.GetOk("raw_payload_maximum_content_length"); ok {
			id := "setting-rawpayloadmaximumcontentlength"
			name := "rawpayloadmaximumcontentlength"
			setting := seq.RawPayloadMaximumContentLengthAsSetting(
				&seq.RawPayloadMaximumContentLength{
					Id:    id,
					Name:  name,
					Value: seq.PtrInt32(int32(v.(int))),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("raw_event_maximum_content_length") {
		if v, ok := d.GetOk("raw_event_maximum_content_length"); ok {
			id := "setting-raweventmaximumcontentlength"
			name := "raweventmaximumcontentlength"
			setting := seq.RawEventMaximumContentLengthAsSetting(
				&seq.RawEventMaximumContentLength{
					Id:    id,
					Name:  name,
					Value: seq.PtrInt32(int32(v.(int))),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("minimum_free_storage_space") {
		if v, ok := d.GetOk("minimum_free_storage_space"); ok {
			id := "setting-minimumfreestoragespace"
			name := "minimumfreestoragespace"
			setting := seq.MinimumFreeStorageSpaceAsSetting(
				&seq.MinimumFreeStorageSpace{
					Id:    id,
					Name:  name,
					Value: seq.PtrInt32(int32(v.(int))),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("theme_styles") {
		if v, ok := d.GetOk("theme_styles"); ok {
			id := "setting-themestyles"
			name := "themestyles"
			setting := seq.ThemeStylesAsSetting(
				&seq.ThemeStyles{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("azuread_authority") {
		if v, ok := d.GetOk("azuread_authority"); ok {
			id := "setting-azureadauthority"
			name := "azureadauthority"
			setting := seq.AzureADAuthorityAsSetting(
				&seq.AzureADAuthority{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("azuread_tenant_id") {
		if v, ok := d.GetOk("azuread_tenant_id"); ok {
			id := "setting-azureadtenantid"
			name := "azureadtenantid"
			setting := seq.AzureADTenantIdAsSetting(
				&seq.AzureADTenantId{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("azuread_client_id") {
		if v, ok := d.GetOk("azuread_client_id"); ok {
			id := "setting-azureadclientid"
			name := "azureadclientid"
			setting := seq.AzureADClientIdAsSetting(
				&seq.AzureADClientId{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("azuread_client_key") {
		if v, ok := d.GetOk("azuread_client_key"); ok {
			id := "setting-azureadclientkey"
			name := "azureadclientkey"
			setting := seq.AzureADClientKeyAsSetting(
				&seq.AzureADClientKey{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("backup_location") {
		if v, ok := d.GetOk("backup_location"); ok {
			id := "setting-backuplocation"
			name := "backuplocation"
			setting := seq.BackupLocationAsSetting(
				&seq.BackupLocation{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("backup_utc_time_of_day") {
		if v, ok := d.GetOk("backup_utc_time_of_day"); ok {
			id := "setting-backuputctimeofday"
			name := "backuputctimeofday"
			setting := seq.BackupUtcTimeOfDayAsSetting(
				&seq.BackupUtcTimeOfDay{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("backups_to_keep") {
		if v, ok := d.GetOk("backups_to_keep"); ok {
			id := "setting-backupstokeep"
			name := "backupstokeep"
			setting := seq.BackupsToKeepAsSetting(
				&seq.BackupsToKeep{
					Id:    id,
					Name:  name,
					Value: seq.PtrInt32(int32(v.(int))),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("new_user_role_ids") {
		if v, ok := d.GetOk("new_user_role_ids"); ok {
			id := "setting-newuserroleids"
			name := "newuserroleids"
			setting := seq.NewUserRoleIdsAsSetting(
				&seq.NewUserRoleIds{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("new_user_show_signal_ids") {
		if v, ok := d.GetOk("new_user_show_signal_ids"); ok {
			id := "setting-newusershowsignalids"
			name := "newusershowsignalids"
			setting := seq.NewUserShowSignalIdsAsSetting(
				&seq.NewUserShowSignalIds{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("new_user_show_query_ids") {
		if v, ok := d.GetOk("new_user_show_query_ids"); ok {
			id := "setting-newusershowqueryids"
			name := "newusershowqueryids"
			setting := seq.NewUserShowQueryIdsAsSetting(
				&seq.NewUserShowQueryIds{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("new_user_show_dashboard_ids") {
		if v, ok := d.GetOk("new_user_show_dashboard_ids"); ok {
			id := "setting-newusershowdashboardids"
			name := "newusershowdashboardids"
			setting := seq.NewUserShowDashboardIdsAsSetting(
				&seq.NewUserShowDashboardIds{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("instance_title") {
		if v, ok := d.GetOk("instance_title"); ok {
			id := "setting-instancetitle"
			name := "instancetitle"
			setting := seq.InstanceTitleAsSetting(
				&seq.InstanceTitle{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("minimum_password_length") {
		if v, ok := d.GetOk("minimum_password_length"); ok {
			id := "setting-minimumpasswordlength"
			name := "minimumpasswordlength"
			setting := seq.MinimumPasswordLengthAsSetting(
				&seq.MinimumPasswordLength{
					Id:    id,
					Name:  name,
					Value: seq.PtrInt32(int32(v.(int))),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("password_required_character_classes") {
		if v, ok := d.GetOk("password_required_character_classes"); ok {
			id := "setting-passwordrequiredcharacterclasses"
			name := "passwordrequiredcharacterclasses"
			setting := seq.PasswordRequiredCharacterClassesAsSetting(
				&seq.PasswordRequiredCharacterClasses{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("openid_connect_authority") {
		if v, ok := d.GetOk("openid_connect_authority"); ok {
			id := "setting-openidconnectauthority"
			name := "openidconnectauthority"
			setting := seq.OpenIdConnectAuthorityAsSetting(
				&seq.OpenIdConnectAuthority{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("openid_connect_client_id") {
		if v, ok := d.GetOk("openid_connect_client_id"); ok {
			id := "setting-openidconnectclientid"
			name := "openidconnectclientid"
			setting := seq.OpenIdConnectClientIdAsSetting(
				&seq.OpenIdConnectClientId{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("openid_connect_client_secret") {
		if v, ok := d.GetOk("openid_connect_client_secret"); ok {
			id := "setting-openidconnectclientsecret"
			name := "openidconnectclientsecret"
			setting := seq.OpenIdConnectClientSecretAsSetting(
				&seq.OpenIdConnectClientSecret{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("openid_connect_scopes") {
		if v, ok := d.GetOk("openid_connect_scopes"); ok {
			id := "setting-openidconnectscopes"
			name := "openidconnectscopes"
			setting := seq.OpenIdConnectScopesAsSetting(
				&seq.OpenIdConnectScopes{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("openid_connect_end_session_redirect_uri") {
		if v, ok := d.GetOk("openid_connect_end_session_redirect_uri"); ok {
			id := "setting-openidconnectendsessionredirecturi"
			name := "openidconnectendsessionredirecturi"
			setting := seq.OpenIdConnectEndSessionRedirectUriAsSetting(
				&seq.OpenIdConnectEndSessionRedirectUri{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("authentication_provider") {
		if v, ok := d.GetOk("authentication_provider"); ok {
			id := "setting-authenticationprovider"
			name := "authenticationprovider"
			setting := seq.AuthenticationProviderAsSetting(
				&seq.AuthenticationProvider{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	if d.HasChange("is_authentication_enabled") {
		if v, ok := d.GetOk("is_authentication_enabled"); ok {
			id := "setting-isauthenticationenabled"
			name := "isauthenticationenabled"
			setting := seq.AutomaticAccessADGroupAsSetting(
				&seq.AutomaticAccessADGroup{
					Id:    id,
					Name:  name,
					Value: seq.PtrString(v.(string)),
				},
			)
			_, resp, err := client.SettingsApi.UpdateSetting(auth, id).Setting(setting).Execute()
			if err != nil {
				return diag.Errorf("error updating setting (ID: %s): %s: %s", id, err, resp.Body)
			}
		}
	}

	return resourceSettingsRead(ctx, d, meta)
}

func resourceSettingsDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// client := meta.(*apiClient).client
	// auth := meta.(*apiClient).auth

	// TODO: Restore previous values on delete

	return nil
}
