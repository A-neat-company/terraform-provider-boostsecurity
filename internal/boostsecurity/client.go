package boostsecurity

import (
	"context"
	"errors"
	"fmt"
	"github.com/Khan/genqlient/graphql"
	"github.com/davecgh/go-spew/spew"
	"net/http"
)

type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	client *graphql.Client
}

type Asset struct {
	provider     string
	organization *string
	resourceName *string
}

type clientWithHeader struct {
	client Doer
	token  string
}

func (c *clientWithHeader) Do(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", fmt.Sprintf("ApiKey %s", c.token))

	return c.client.Do(req)
}

func NewClient(url string, token string) *Client {
	client := graphql.NewClient(url, &clientWithHeader{client: http.DefaultClient, token: token})
	return &Client{client: &client}
}

func (c *Client) ApplyPlan(ctx context.Context, assetId string, assetType AssetType, policyId string, applyScannerIds []string, clearScannerIds []string) error {
	selection := make([]AssetSelection, 1)
	selection[0] = AssetSelection{SelectionType: SelectionTypeAsset, AssetIds: []string{assetId}, AssetType: assetType}

	scannerOperation := make([]ScannerOperation, 0)
	for _, scannerId := range applyScannerIds {
		scannerOperation = append(scannerOperation, ScannerOperation{Action: OperationActionApply, ScannerId: scannerId})
	}
	for _, scannerId := range clearScannerIds {
		scannerOperation = append(scannerOperation, ScannerOperation{Action: OperationActionClear, ScannerId: scannerId})
	}

	policyOperation := PolicyOperation{Action: OperationActionClear, PolicyId: policyId}
	if len(policyId) > 0 {
		policyOperation = PolicyOperation{Action: OperationActionApply, PolicyId: policyId}
	}

	res, err := ApplyProvisionPlan(ctx, *c.client, selection, scannerOperation, policyOperation, false)
	if err != nil {
		return err
	}

	if res.ApplyProvisionPlan.GetTypename() == "OperationError" {
		response := res.ApplyProvisionPlan.(*ApplyProvisionPlanApplyProvisionPlanOperationError)
		return errors.New(spew.Sdump(response))
	}

	return nil

}

func (c *Client) GetProvisionPlan(context context.Context, assetId string, assetType AssetType) ([]string, error) {
	selection := make([]AssetSelection, 1)
	selection[0] = AssetSelection{SelectionType: SelectionTypeAsset, AssetIds: []string{assetId}, AssetType: assetType}
	res, err := ProvisionPlan(context, *c.client, selection)
	if err != nil {
		return nil, err
	}
	scanners := make([]string, 0)
	for _, scanner := range res.ProvisionPlan.Scanners {
		if scanner.Availability == ProvisionPlanScannerAvailabilityAvailable {
			scanners = append(scanners, scanner.ScannerId)
		}
	}
	return scanners, nil
}

func (c *Client) GetPosture(ctx context.Context) (*ProvidersModel, error) {
	var data = ProvidersModel{}
	result, err := SecurityPosture(ctx, *c.client)
	if err != nil {
		return nil, fmt.Errorf("error in SecurityPosture %w", err)
	}

	data.Providers = make([]ProviderModel, 0)
	for _, item := range result.SecurityPosture.Providers.Edges {
		node := item.Node
		var organization []OrganizationModel
		organization, err = c.getProviderCollections(ctx, node.ProviderId)
		if err != nil {
			return nil, fmt.Errorf("error in getProviderCollections %w", err)
		}
		provider := ProviderModel{
			Name:          node.Name,
			ID:            node.ProviderId,
			Organizations: organization,
		}

		data.Providers = append(data.Providers, provider)

	}
	return &data, nil
}

func (c *Client) getProviderCollections(ctx context.Context, providerId string) ([]OrganizationModel, error) {
	result, err := ProviderCollections(ctx, *c.client, providerId, 100)
	if err != nil {
		return nil, fmt.Errorf("error getting provider collections %w", err)
	}

	organizations := make([]OrganizationModel, 0)
	for _, collection := range result.Provider.Collections.Edges {
		node := collection.Node
		scanners := make([]string, 0)
		for _, s := range node.Scanners {
			if s.State == ProvisioningStateProvisioned {
				scanners = append(scanners, s.ScannerId)
			}
		}

		var resources []ResourcesModel
		resources, err = c.getCollection(ctx, providerId, node.CollectionId)
		if err != nil {
			return nil, fmt.Errorf("error getting collection %w", err)
		}
		organizations = append(organizations, OrganizationModel{
			Name:      node.Name,
			ID:        node.CollectionId,
			Scanners:  scanners,
			Policy:    node.Policy.PolicyId,
			Resources: resources,
		})
	}

	return organizations, nil
}

func (c *Client) getCollection(ctx context.Context, providerId string, collectionId string) ([]ResourcesModel, error) {
	result, err := ProviderCollection(ctx, *c.client, providerId, collectionId, 100)
	if err != nil {
		return nil, fmt.Errorf("error getting collection resources %w", err)
	}

	resources := make([]ResourcesModel, 0)
	for _, rcs := range result.Provider.Collection.Resources.Edges {
		node := rcs.Node
		scanners := make([]string, 0)
		for _, s := range node.Scanners {
			if s.State == ProvisioningStateProvisioned {
				scanners = append(scanners, s.ScannerId)
			}
		}
		resources = append(resources, ResourcesModel{
			Name:     node.Name,
			ID:       node.ResourceId,
			Scanners: scanners,
			Policy:   node.Policy.PolicyId,
		})
	}

	return resources, nil
}
