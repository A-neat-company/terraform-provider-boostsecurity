package boostsecurity

import "github.com/hashicorp/terraform-plugin-framework/types"

type ProvidersModel struct {
	Providers []ProviderModel
}

type ProviderModel struct {
	Name          string
	ID            string
	Organizations []OrganizationModel
}

type OrganizationModel struct {
	Name      string
	ID        string
	Scanners  []string
	Policy    string
	Resources []ResourcesModel
}

type ResourcesModel struct {
	Name     string
	ID       string
	Scanners []string
	Policy   string
}

type State struct {
	Asset AssetModel `tfsdk:"asset"`
}

type AssetModel struct {
	Provider       types.String `tfsdk:"provider"`
	Collection     types.String `tfsdk:"collection"`
	Resource       types.String `tfsdk:"resource"`
	ID             types.String `tfsdk:"id"`
	Scanners       types.List   `tfsdk:"scanners"`
	Policy         types.String `tfsdk:"policy"`
	AssignedPolicy types.String `tfsdk:"assigned_policy"`
}
