package provider

import (
	"context"
	"errors"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"slices"
	"terraform-provider-boostsecurity/internal/boostsecurity"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource               = &scannerCoverageResource{}
	_ resource.ResourceWithConfigure  = &scannerCoverageResource{}
	_ resource.ResourceWithModifyPlan = &scannerCoverageResource{}
)

// NewScannerCoverageResource is a helper function to simplify the provider implementation.
func NewScannerCoverageResource() resource.Resource {
	return &scannerCoverageResource{}
}

// scannerCoverageResource is the resource implementation.
type scannerCoverageResource struct {
	client *boostsecurity.Client
	cache  *boostsecurity.ProvidersModel
}

// Metadata returns the resource type name.
func (r *scannerCoverageResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fortify"
}

// Schema defines the schema for the resource.
func (r *scannerCoverageResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages Scanner coverage.",
		Attributes: map[string]schema.Attribute{
			"asset": schema.SingleNestedAttribute{
				Required:    true,
				Description: "An asset",
				Attributes: map[string]schema.Attribute{
					"provider": schema.StringAttribute{
						Description: "The provider of the resource.",
						Required:    true,
					},
					"collection": schema.StringAttribute{
						Description: "The collection of the resource.",
						Required:    true,
					},
					"resource": schema.StringAttribute{
						Description: "The name of the resource.",
						Optional:    true,
					},
					"id": schema.StringAttribute{
						Description: "The ID of the resource.",
						Computed:    true,
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
					"scanners": schema.ListAttribute{
						Description: "List of scanners for the asset.",
						ElementType: types.StringType,
						Required:    true,
					},
					"policy": schema.StringAttribute{
						Description: "The policy of the asset.",
						Optional:    true,
					},
					"assigned_policy": schema.StringAttribute{
						Description: "The policy of the asset.",
						Computed:    true,
					},
				},
			},
		},
	}

}

func (r *scannerCoverageResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	tflog.Debug(ctx, "MODIFY PLAN.")

	if req.Plan.Raw.IsNull() {
		return
	}
	var state boostsecurity.State
	diags := req.Plan.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	assetId, err := r.getAssetId(&state.Asset)
	if err != nil {
		resp.Diagnostics.AddError("Error finding asset in cache", "Could not find asset : "+err.Error())
		return
	}

	diags = r.validateScannerIds(ctx, state, assetId)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.Plan.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Create a new resource.
func (r *scannerCoverageResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Debug(ctx, "CREATING")
	var state boostsecurity.State
	diags := req.Plan.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	asset, err := r.findInCache(&state.Asset)
	if err != nil {
		resp.Diagnostics.AddError("Error finding asset in cache", "Could not find asset : "+err.Error())
		return
	}

	diags = r.validateScannerIds(ctx, state, asset.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyId := ""
	if !state.Asset.Policy.IsNull() {
		policyId = state.Asset.Policy.ValueString()
	}

	var scannerIds []string
	scannerIds, diags = toStringArray(ctx, state.Asset.Scanners)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !state.Asset.Policy.IsNull() || len(state.Asset.Scanners.Elements()) > 0 {
		assetType := boostsecurity.AssetTypeResource
		if state.Asset.Resource.IsNull() {
			assetType = boostsecurity.AssetTypeCollection

		}
		err = r.client.ApplyPlan(ctx, asset.ID.ValueString(), assetType, policyId, scannerIds, []string{})
		if err != nil {
			tflog.Debug(ctx, spew.Sdump(err))
			resp.Diagnostics.AddError("Error applying plan", "RIP : "+err.Error())
			return
		}
	}

	state.Asset.ID = asset.ID
	state.Asset.AssignedPolicy = asset.Policy

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read resource information.
func (r *scannerCoverageResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	tflog.Debug(ctx, "READING")
	var state boostsecurity.State
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	posture, err := r.client.GetPosture(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unexpected error getting posture",
			fmt.Sprintf("While building cache, got: %T.", err),
		)

		return
	}
	r.cache = posture

	asset, err := r.findInCache(&state.Asset)
	if err != nil {
		resp.Diagnostics.AddError("Error finding asset in cache", "Could not find asset : "+err.Error())
		return
	}

	diags = r.validateScannerIds(ctx, state, asset.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.Asset.ID = asset.ID
	state.Asset.AssignedPolicy = asset.Policy

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *scannerCoverageResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plannedState boostsecurity.State
	diags := req.Plan.Get(ctx, &plannedState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var oldState boostsecurity.State
	diags = req.State.Get(ctx, &oldState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var previousSannerIds []string
	previousSannerIds, diags = toStringArray(ctx, oldState.Asset.Scanners)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var plannedScannerIds []string
	plannedScannerIds, diags = toStringArray(ctx, plannedState.Asset.Scanners)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// if previous scanner is not planned, we clear it
	toClear := make([]string, 0)
	for _, scannerId := range previousSannerIds {
		if !slices.Contains(plannedScannerIds, scannerId) {
			toClear = append(toClear, scannerId)
		}
	}

	asset, err := r.findInCache(&plannedState.Asset)
	if err != nil {
		resp.Diagnostics.AddError("Error finding asset in cache", "Could not find asset : "+err.Error())
		return
	}

	diags = r.validateScannerIds(ctx, plannedState, asset.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(plannedState.Asset.Scanners.Elements()) > 0 {
		assetType := boostsecurity.AssetTypeResource
		if plannedState.Asset.Resource.IsNull() {
			assetType = boostsecurity.AssetTypeCollection

		}
		err = r.client.ApplyPlan(ctx, asset.ID.ValueString(), assetType, plannedState.Asset.Policy.ValueString(), plannedScannerIds, toClear)
		if err != nil {
			tflog.Debug(ctx, spew.Sdump(err))
			resp.Diagnostics.AddError("Error applying update plan", "RIP : "+err.Error())
			return
		}
	}

	plannedState.Asset.ID = asset.ID
	plannedState.Asset.AssignedPolicy = asset.Policy

	diags = resp.State.Set(ctx, &plannedState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *scannerCoverageResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state boostsecurity.State
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, spew.Sdump(state))

	assetType := boostsecurity.AssetTypeResource
	if state.Asset.Resource.IsNull() {
		assetType = boostsecurity.AssetTypeCollection

	}

	var toClear []string
	toClear, diags = toStringArray(ctx, state.Asset.Scanners)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.ApplyPlan(ctx, state.Asset.ID.ValueString(), assetType, "", []string{}, toClear)
	if err != nil {
		tflog.Debug(ctx, spew.Sdump(err))
		resp.Diagnostics.AddError("Error deleting plan", "RIP : "+err.Error())
		return
	}
}

// Configure adds the provider configured client to the resource.
func (r *scannerCoverageResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*boostsecurity.Client)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected GQL Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	tflog.Debug(ctx, "Building cache")
	posture, err := client.GetPosture(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unexpected error getting posture",
			fmt.Sprintf("While building cache, got: %T.", err),
		)

		return
	}

	r.client = client
	r.cache = posture
}

func (r *scannerCoverageResource) validateScannerIds(ctx context.Context, state boostsecurity.State, assetId string) diag.Diagnostics {
	tflog.Debug(ctx, "Validating.")
	diags := diag.Diagnostics{}

	if len(state.Asset.Scanners.Elements()) > 0 {
		assetType := boostsecurity.AssetTypeResource
		if state.Asset.Resource.IsNull() {
			assetType = boostsecurity.AssetTypeCollection

		}
		availableScanners, err := r.client.GetProvisionPlan(ctx, assetId, assetType)
		if err != nil {
			diags.AddError("Error getting plan for asset", "Could not get plan : "+err.Error())
			return diags
		}

		var scannerIds []string
		scannerIds, diags = toStringArray(ctx, state.Asset.Scanners)
		if diags.HasError() {
			return diags
		}
		for _, scannerId := range scannerIds {
			if !slices.Contains(availableScanners, scannerId) {
				diags.AddError("Scanner not available for asset", "Scanner not available for asset : "+scannerId)
			}
		}
	}
	return diags
}

func (r *scannerCoverageResource) getAssetId(asset *boostsecurity.AssetModel) (string, error) {
	if providerIndex := slices.IndexFunc(r.cache.Providers, providerCompare(asset.Provider)); providerIndex != -1 {
		provider := r.cache.Providers[providerIndex]
		if collectionIndex := slices.IndexFunc(provider.Organizations, collectionCompare(asset.Collection)); collectionIndex != -1 {
			collection := provider.Organizations[collectionIndex]
			if asset.Resource.IsNull() {
				return collection.ID, nil
			}
			if resourceIndex := slices.IndexFunc(collection.Resources, resourceCompare(asset.Resource)); resourceIndex != -1 {
				rcs := collection.Resources[resourceIndex]
				return rcs.ID, nil
			}
		}
	}

	return "", errors.New("could not find asset id. Make sure the asset is managed by an integration")
}

func (r *scannerCoverageResource) findInCache(asset *boostsecurity.AssetModel) (boostsecurity.AssetModel, error) {
	if providerIndex := slices.IndexFunc(r.cache.Providers, providerCompare(asset.Provider)); providerIndex != -1 {
		provider := r.cache.Providers[providerIndex]
		if collectionIndex := slices.IndexFunc(provider.Organizations, collectionCompare(asset.Collection)); collectionIndex != -1 {
			collection := provider.Organizations[collectionIndex]
			if asset.Resource.IsNull() {
				scanners := make([]attr.Value, 0)
				for _, scanner := range collection.Scanners {
					scanners = append(scanners, types.StringValue(scanner))
				}
				return boostsecurity.AssetModel{
					Provider:   types.StringValue(provider.Name),
					Collection: types.StringValue(collection.Name),
					Resource:   types.StringNull(),
					ID:         types.StringValue(collection.ID),
					Scanners:   types.ListValueMust(types.StringType, scanners),
					Policy:     types.StringValue(collection.Policy),
				}, nil
			}
			if resourceIndex := slices.IndexFunc(collection.Resources, resourceCompare(asset.Resource)); resourceIndex != -1 {
				rcs := collection.Resources[resourceIndex]
				scanners := make([]attr.Value, 0)

				for _, scanner := range rcs.Scanners {
					scanners = append(scanners, types.StringValue(scanner))
				}
				return boostsecurity.AssetModel{
					Provider:   types.StringValue(provider.Name),
					Collection: types.StringValue(collection.Name),
					Resource:   types.StringValue(rcs.Name),
					ID:         types.StringValue(rcs.ID),
					Scanners:   types.ListValueMust(types.StringType, scanners),
					Policy:     types.StringValue(collection.Policy),
				}, nil
			}
		}
	}

	return boostsecurity.AssetModel{}, errors.New("could not find asset. Make sure the asset is managed by an integration")
}

func toStringArray(ctx context.Context, in types.List) ([]string, diag.Diagnostics) {
	scannerIds := make([]string, 0)
	var diags diag.Diagnostics
	if len(in.Elements()) > 0 {
		temp := make([]types.String, len(in.Elements()))
		diags = in.ElementsAs(ctx, &temp, false)
		for _, scannerId := range temp {
			scannerIds = append(scannerIds, scannerId.ValueString())
		}
	}

	return scannerIds, diags
}

func providerCompare(value types.String) func(model boostsecurity.ProviderModel) bool {
	return func(model boostsecurity.ProviderModel) bool {
		return model.Name == value.ValueString()
	}
}
func collectionCompare(value types.String) func(model boostsecurity.OrganizationModel) bool {
	return func(model boostsecurity.OrganizationModel) bool {
		return model.Name == value.ValueString()
	}
}
func resourceCompare(value types.String) func(model boostsecurity.ResourcesModel) bool {
	return func(model boostsecurity.ResourcesModel) bool {
		return model.Name == value.ValueString()
	}
}
