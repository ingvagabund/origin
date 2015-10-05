package etcd

import (
	"github.com/openshift/origin/pkg/service/catalog/api"
	"github.com/openshift/origin/pkg/service/catalog/registry/catalog"
	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	etcdgeneric "k8s.io/kubernetes/pkg/registry/generic/etcd"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/storage"
	"k8s.io/kubernetes/pkg/watch"
)

// REST implements a RESTStorage for catalog services against etcd
type REST struct {
	store *etcdgeneric.Etcd
}

// NewREST returns a new REST.
func NewREST(s storage.Interface) (*REST, *StatusREST) {
	prefix := "/servicecatalog"
	store := etcdgeneric.Etcd{
		NewFunc:     func() runtime.Object { return &api.CatalogService{} },
		NewListFunc: func() runtime.Object { return &api.CatalogServiceList{} },
		KeyRootFunc: func(ctx kapi.Context) string {
			return etcdgeneric.NamespaceKeyRootFunc(ctx, prefix)
		},
		KeyFunc: func(ctx kapi.Context, name string) (string, error) {
			return etcdgeneric.NamespaceKeyFunc(ctx, prefix, name)
		},
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*api.CatalogService).Name, nil
		},
		EndpointName: "serviceCatalog",

		ReturnDeletedObject: false,
		Storage:             s,
	}

	strategy := catalog.NewStrategy()
	rest := &REST{}

	statusStore := store
	//statusStore.UpdateStrategy = catalog.NewStatusStrategy(strategy)

	store.CreateStrategy = strategy
	store.UpdateStrategy = strategy

	rest.store = &store

	return rest, &StatusREST{store: &statusStore}
}

// New returns a new object
func (r *REST) New() runtime.Object {
	return r.store.NewFunc()
}

// NewList returns a new list object
func (r *REST) NewList() runtime.Object {
	return r.store.NewListFunc()
}

// List obtains a list of image streams with labels that match selector.
func (r *REST) List(ctx kapi.Context, label labels.Selector, field fields.Selector) (runtime.Object, error) {
	return r.store.ListPredicate(ctx, catalog.MatchCatalogService(label, field))
}

// Watch begins watching for new, changed, or deleted image streams.
func (r *REST) Watch(ctx kapi.Context, label labels.Selector, field fields.Selector, resourceVersion string) (watch.Interface, error) {
	return r.store.WatchPredicate(ctx, catalog.MatchCatalogService(label, field), resourceVersion)
}

// Get gets a specific catalog service specified by its ID.
func (r *REST) Get(ctx kapi.Context, name string) (runtime.Object, error) {
	return r.store.Get(ctx, name)
}

// Create creates a catalog service based on a specification.
func (r *REST) Create(ctx kapi.Context, obj runtime.Object) (runtime.Object, error) {
	return r.store.Create(ctx, obj)
}

// Update changes a catalog service specification.
func (r *REST) Update(ctx kapi.Context, obj runtime.Object) (runtime.Object, bool, error) {
	return r.store.Update(ctx, obj)
}

// Delete deletes an existing catalog service specified by its ID.
func (r *REST) Delete(ctx kapi.Context, name string, options *kapi.DeleteOptions) (runtime.Object, error) {
	return r.store.Delete(ctx, name, options)
}

// StatusREST implements the REST endpoint for changing the status of an catalog service.
type StatusREST struct {
	store *etcdgeneric.Etcd
}

func (r *StatusREST) New() runtime.Object {
	return &api.CatalogService{}
}

// Update alters the status subset of an object.
func (r *StatusREST) Update(ctx kapi.Context, obj runtime.Object) (runtime.Object, bool, error) {
	return r.store.Update(ctx, obj)
}
