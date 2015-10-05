package catalog

import (
	"github.com/openshift/origin/pkg/service/catalog/api"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/rest"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/watch"
)

// Registry is an interface for things that know how to store CatalogService objects
type Registry interface {
	// ListCatalogServices obtains a list of service that match a selector
	ListCatalogServices(ctx kapi.Context, selector labels.Selector) (*api.CatalogServiceList, error)
	// GetCatalogService retrieves a specific catalog service
	GetCatalogService(ctx kapi.Context, id string) (*api.CatalogService, error)
	// CreateCatalogService add service into catalog
	CreateCatalogService(ctx kapi.Context, service *api.CatalogService) (*api.CatalogService, error)
	// UpdateCatalogService updates a service in catalog
	UpdateCatalogService(ctx kapi.Context, service *api.CatalogService) (*api.CatalogService, error)
	// DeleteCatalogService deletes service from catalog
	DeleteCatalogService(ctx kapi.Context, id string) (*kapi.Status, error)
	// WatchCatalogServices watches for new/changed/deleted catalog services
	WatchCatalogServices(ctx kapi.Context, label labels.Selector, field fields.Selector, resourceVersion string) (watch.Interface, error)
}

// Storage is an interface for a standard REST Storage backend
type Storage interface {
	rest.GracefulDeleter
	rest.Lister
	rest.Getter
	rest.Watcher

	Create(ctx kapi.Context, obj runtime.Object) (runtime.Object, error)
	Update(ctx kapi.Context, obj runtime.Object) (runtime.Object, bool, error)
}

// storage puts strong typing around storage calls
type storage struct {
	Storage
	status rest.Updater
}

// NewRegistry returns a new Registry interface for the given Storage. Any mismatched
// types will panic.
func NewRegistry(s Storage, status rest.Updater) Registry {
	return &storage{s, status}
}

func (s *storage) ListCatalogServices(ctx kapi.Context, label labels.Selector) (*api.CatalogServiceList, error) {
	obj, err := s.List(ctx, label, fields.Everything())
	if err != nil {
		return nil, err
	}
	return obj.(*api.CatalogServiceList), nil
}

func (s *storage) GetCatalogService(ctx kapi.Context, catalogServiceID string) (*api.CatalogService, error) {
	obj, err := s.Get(ctx, catalogServiceID)
	if err != nil {
		return nil, err
	}
	return obj.(*api.CatalogService), nil
}

func (s *storage) CreateCatalogService(ctx kapi.Context, catalogService *api.CatalogService) (*api.CatalogService, error) {
	obj, err := s.Create(ctx, catalogService)
	if err != nil {
		return nil, err
	}
	return obj.(*api.CatalogService), nil
}

func (s *storage) UpdateCatalogService(ctx kapi.Context, catalogService *api.CatalogService) (*api.CatalogService, error) {
	obj, _, err := s.Update(ctx, catalogService)
	if err != nil {
		return nil, err
	}
	return obj.(*api.CatalogService), nil
}

func (s *storage) DeleteCatalogService(ctx kapi.Context, catalogServiceID string) (*kapi.Status, error) {
	obj, err := s.Delete(ctx, catalogServiceID, nil)
	if err != nil {
		return nil, err
	}
	return obj.(*kapi.Status), nil
}

func (s *storage) WatchCatalogServices(ctx kapi.Context, label labels.Selector, field fields.Selector, resourceVersion string) (watch.Interface, error) {
	return s.Watch(ctx, label, field, resourceVersion)
}
