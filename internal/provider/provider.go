package provider

import (
	"context"
	"net/url"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/innovationnorway/go-seq"
)

func init() {
	schema.DescriptionKind = schema.StringMarkdown
}

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			Schema: map[string]*schema.Schema{
				"server_url": {
					Type:        schema.TypeString,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("SEQ_SERVER_URL", nil),
					Description: "The HTTP endpoint address of the Seq server. This can also be set with the `SEQ_SERVER_URL` environment variable.",
				},
				"api_key": {
					Type:        schema.TypeString,
					Optional:    true,
					Sensitive:   true,
					DefaultFunc: schema.EnvDefaultFunc("SEQ_API_KEY", nil),
					Description: "The API Key to use when connecting to Seq. This can also be set with the `SEQ_API_KEY` environment variable.",
				},
			},
			DataSourcesMap: map[string]*schema.Resource{
				// TODO: add data sources
			},
			ResourcesMap: map[string]*schema.Resource{
				"seq_admin_user": resourceAdminUser(),
				"seq_api_key":    resourceAPIKey(),
				"seq_license":    resourceLicense(),
				"seq_settings":   resourceSettings(),
				"seq_user":       resourceUser(),
			},
		}

		p.ConfigureContextFunc = configure(version, p)

		return p
	}
}

type apiClient struct {
	client *seq.APIClient
	auth   context.Context
}

func configure(version string, p *schema.Provider) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		u, err := url.Parse(d.Get("server_url").(string))
		if err != nil {
			return nil, diag.Errorf("error parsing host: %s", err)
		}

		config := seq.NewConfiguration()
		config.UserAgent = p.UserAgent("terraform-provider-seq", version)
		config.HTTPClient = cleanhttp.DefaultClient()
		config.HTTPClient.Transport = logging.NewTransport("Seq", config.HTTPClient.Transport)
		config.Host = u.Host
		config.Scheme = u.Scheme

		client := seq.NewAPIClient(config)
		auth := context.WithValue(
			context.Background(),
			seq.ContextAPIKeys,
			map[string]seq.APIKey{
				"ApiKeyAuth": {
					Key: d.Get("api_key").(string),
				},
			},
		)

		return &apiClient{
			client: client,
			auth:   auth,
		}, nil
	}
}
