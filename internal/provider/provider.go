package provider

import (
	"context"
	"os"
	"terraform-provider-boostsecurity/internal/boostsecurity"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ provider.Provider = &boostsecurityProvider{}
)

// New is a helper function to simplify provider server and testing implementation.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &boostsecurityProvider{
			version: version,
		}
	}
}

// boostsecurityProviderModel maps provider schema data to a Go type.
type boostsecurityProviderModel struct {
	Host  types.String `tfsdk:"host"`
	Token types.String `tfsdk:"token"`
}

// boostsecurityProvider is the provider implementation.
type boostsecurityProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// Metadata returns the provider type name.
func (p *boostsecurityProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "boostsecurity"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data.
func (p *boostsecurityProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Interact with Boostsecurity.",
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Description: "URI for Boost API.",
				Optional:    true,
			},
			"token": schema.StringAttribute{
				Description: "API token for Boost API.",
				Optional:    true,
			},
		},
	}
}

func (p *boostsecurityProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	tflog.Info(ctx, "Configuring HashiCups client")

	// Retrieve provider data from configuration
	var config boostsecurityProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If practitioner provided a configuration value for any of the
	// attributes, it must be a known value.

	if config.Host.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("host"),
			"Unknown HashiCups API Host",
			"The provider cannot create the HashiCups API client as there is an unknown configuration value for the HashiCups API host. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the HASHICUPS_HOST environment variable.",
		)
	}

	if config.Token.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("username"),
			"Unknown HashiCups API Username",
			"The provider cannot create the HashiCups API client as there is an unknown configuration value for the HashiCups API username. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the HASHICUPS_USERNAME environment variable.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Default values to environment variables, but override
	// with Terraform configuration value if set.

	host := os.Getenv("BOOST_HOST")
	token := os.Getenv("BOOST_TOKEN")

	if !config.Host.IsNull() {
		host = config.Host.ValueString()
	}

	if !config.Token.IsNull() {
		token = config.Token.ValueString()
	}

	// If any of the expected configurations are missing, return
	// errors with provider-specific guidance.

	if host == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("host"),
			"Missing Boost API Host",
			"The provider cannot create the Boost API client as there is a missing or empty value for the Boost API host. "+
				"Set the host value in the configuration or use the BOOST_HOST environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if token == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("token"),
			"Missing Boost Token",
			"The provider cannot create the Boost API client as there is a missing or empty value for the Boost API token. "+
				"Set the username value in the configuration or use the BOOST_TOKEN environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "boost_host", host)
	ctx = tflog.SetField(ctx, "boost_token", token)
	ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "boost_token")

	tflog.Debug(ctx, "Creating GQL client")

	// Create a new HashiCups client using the configuration values
	client := boostsecurity.NewClient(host, token)

	// Make the HashiCups client available during DataSource and Resource
	// type Configure methods.
	resp.ResourceData = client

	tflog.Info(ctx, "Configured Boost client", map[string]any{"success": true})
}

// DataSources defines the data sources implemented in the provider.
func (p *boostsecurityProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// Resources defines the resources implemented in the provider.
func (p *boostsecurityProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewScannerCoverageResource,
	}
}
