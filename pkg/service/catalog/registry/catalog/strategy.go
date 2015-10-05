package catalog

import (
	"fmt"

	"github.com/openshift/origin/pkg/service/catalog/api"
	kapi "k8s.io/kubernetes/pkg/api"
	kerrors "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/registry/generic"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/fielderrors"
)

// Strategy implements behavior for CatalogService.
type Strategy struct {
	runtime.ObjectTyper
	kapi.NameGenerator
}

// NewStrategy is the default logic that applies when creating and updating
// CatalogService objects via the REST API.
func NewStrategy() Strategy {
	return Strategy{
		ObjectTyper:   kapi.Scheme,
		NameGenerator: kapi.SimpleNameGenerator,
	}
}

// NamespaceScoped is false for catalog services
func (s Strategy) NamespaceScoped() bool {
	return false
}

// PrepareForCreate clears fields that are not allowed to be set by end users on creation,
// and verifies the current user is authorized to access any catalog service newly referenced
// in spec.tags.
func (s Strategy) PrepareForCreate(obj runtime.Object) {
	// nothing to clear/set atm
	//catalog := obj.(*api.CatalogService)
}

// Validate validates a new catalog service.
func (s Strategy) Validate(ctx kapi.Context, obj runtime.Object) fielderrors.ValidationErrorList {
	catalog := obj.(*api.CatalogService)
	_, ok := kapi.UserFrom(ctx)
	if !ok {
		return fielderrors.ValidationErrorList{kerrors.NewForbidden("serviceCatalog", catalog.Name, fmt.Errorf("unable to update an CatalogService without a user on the context"))}
	}
	// TODO: add validation on description and non-empty target
	// TODO: validate the targeted service actually exists
	//return errs
	return nil
}

// AllowCreateOnUpdate is false for catalog services.
func (s Strategy) AllowCreateOnUpdate() bool {
	return false
}

func (Strategy) AllowUnconditionalUpdate() bool {
	return false
}

func (s Strategy) PrepareForUpdate(obj, old runtime.Object) {
	// nothing to clear/set atm
}

// ValidateUpdate is the default update validation for an end user.
func (s Strategy) ValidateUpdate(ctx kapi.Context, obj, old runtime.Object) fielderrors.ValidationErrorList {
	catalog := obj.(*api.CatalogService)

	_, ok := kapi.UserFrom(ctx)
	if !ok {
		return fielderrors.ValidationErrorList{kerrors.NewForbidden("serviceCatalog", catalog.Name, fmt.Errorf("unable to update an CatalogService without a user on the context"))}
	}
	// TODO: add validation on description and non-empty target
	// TODO: validate the targeted service actually exists
	//oldCatalog := old.(*api.CatalogService)
	//return errs
	return nil
}

// MatchCatalogService returns a generic matcher for a given label and field selector.
func MatchCatalogService(label labels.Selector, field fields.Selector) generic.Matcher {
	return generic.MatcherFunc(func(obj runtime.Object) (bool, error) {
		cs, ok := obj.(*api.CatalogService)
		if !ok {
			return false, fmt.Errorf("not an CatalogService")
		}
		fields := CatalogServiceToSelectableFields(cs)
		return label.Matches(labels.Set(cs.Labels)) && field.Matches(fields), nil
	})
}

// CatalogServiceToSelectableFields returns a label set that represents the object.
func CatalogServiceToSelectableFields(cs *api.CatalogService) labels.Set {
	// TODO:
	// does it make sense to label target and description?
	return labels.Set{
		"metadata.name":            cs.Name,
		"catalogservice.claimtype": cs.ClaimType,
	}
}
