// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package dgraph

import (
	"fmt"
	"io"
	"strconv"
	"time"
)

type AddDomainFederationInput struct {
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
	Domain           string    `json:"domain"`
	Description      string    `json:"description"`
	Keys             []string  `json:"keys"`
	ServiceEndpoints []string  `json:"serviceEndpoints"`
	AllowedList      []string  `json:"allowedList"`
	Status           int       `json:"status"`
}

type AddDomainFederationPayload struct {
	DomainFederation []*DomainFederation `json:"domainFederation"`
	NumUids          *int                `json:"numUids"`
}

type AddServiceRegistryInput struct {
	CreatedAt        time.Time                       `json:"createdAt"`
	UpdatedAt        time.Time                       `json:"updatedAt"`
	SubjectID        string                          `json:"subjectId"`
	SubjectType      string                          `json:"subjectType"`
	Description      string                          `json:"description"`
	Keys             []string                        `json:"keys"`
	KeysUpdatedAt    time.Time                       `json:"keysUpdatedAt"`
	Status           int                             `json:"status"`
	ServiceEndpoints []string                        `json:"serviceEndpoints"`
	Permissions      []*ServiceRegistryPermissionRef `json:"permissions"`
	Uk               string                          `json:"uk"`
}

type AddServiceRegistryPayload struct {
	ServiceRegistry []*ServiceRegistry `json:"serviceRegistry"`
	NumUids         *int               `json:"numUids"`
}

type AddServiceRegistryPermissionInput struct {
	CreatedAt  time.Time           `json:"createdAt"`
	UpdatedAt  time.Time           `json:"updatedAt"`
	Resource   string              `json:"resource"`
	Operations []string            `json:"operations"`
	Extensions []string            `json:"extensions"`
	Registry   *ServiceRegistryRef `json:"registry"`
	Uk         string              `json:"uk"`
}

type AddServiceRegistryPermissionPayload struct {
	ServiceRegistryPermission []*ServiceRegistryPermission `json:"serviceRegistryPermission"`
	NumUids                   *int                         `json:"numUids"`
}

type AddUserRegistryBundleInput struct {
	CreatedAt time.Time           `json:"createdAt"`
	UpdatedAt time.Time           `json:"updatedAt"`
	Provider  *ServiceRegistryRef `json:"provider"`
	BundleID  string              `json:"bundleId"`
	Extension string              `json:"extension"`
	Registry  *UserRegistryRef    `json:"registry"`
	Uk        string              `json:"uk"`
}

type AddUserRegistryBundlePayload struct {
	UserRegistryBundle []*UserRegistryBundle `json:"userRegistryBundle"`
	NumUids            *int                  `json:"numUids"`
}

type AddUserRegistryInput struct {
	CreatedAt     time.Time                `json:"createdAt"`
	UpdatedAt     time.Time                `json:"updatedAt"`
	SubjectID     string                   `json:"subjectId"`
	SubjectType   string                   `json:"subjectType"`
	Description   string                   `json:"description"`
	Keys          []string                 `json:"keys"`
	KeysUpdatedAt time.Time                `json:"keysUpdatedAt"`
	Status        int                      `json:"status"`
	ReleaseID     string                   `json:"releaseId"`
	Bundles       []*UserRegistryBundleRef `json:"bundles"`
	Uk            string                   `json:"uk"`
}

type AddUserRegistryPayload struct {
	UserRegistry []*UserRegistry `json:"userRegistry"`
	NumUids      *int            `json:"numUids"`
}

type AuthRule struct {
	And  []*AuthRule `json:"and"`
	Or   []*AuthRule `json:"or"`
	Not  *AuthRule   `json:"not"`
	Rule *string     `json:"rule"`
}

type CustomHTTP struct {
	URL                  string     `json:"url"`
	Method               HTTPMethod `json:"method"`
	Body                 *string    `json:"body"`
	Graphql              *string    `json:"graphql"`
	Mode                 *Mode      `json:"mode"`
	ForwardHeaders       []string   `json:"forwardHeaders"`
	SecretHeaders        []string   `json:"secretHeaders"`
	IntrospectionHeaders []string   `json:"introspectionHeaders"`
	SkipIntrospection    *bool      `json:"skipIntrospection"`
}

type DateTimeFilter struct {
	Eq *time.Time `json:"eq"`
	Le *time.Time `json:"le"`
	Lt *time.Time `json:"lt"`
	Ge *time.Time `json:"ge"`
	Gt *time.Time `json:"gt"`
}

type DeleteDomainFederationPayload struct {
	DomainFederation []*DomainFederation `json:"domainFederation"`
	Msg              *string             `json:"msg"`
	NumUids          *int                `json:"numUids"`
}

type DeleteServiceRegistryPayload struct {
	ServiceRegistry []*ServiceRegistry `json:"serviceRegistry"`
	Msg             *string            `json:"msg"`
	NumUids         *int               `json:"numUids"`
}

type DeleteServiceRegistryPermissionPayload struct {
	ServiceRegistryPermission []*ServiceRegistryPermission `json:"serviceRegistryPermission"`
	Msg                       *string                      `json:"msg"`
	NumUids                   *int                         `json:"numUids"`
}

type DeleteUserRegistryBundlePayload struct {
	UserRegistryBundle []*UserRegistryBundle `json:"userRegistryBundle"`
	Msg                *string               `json:"msg"`
	NumUids            *int                  `json:"numUids"`
}

type DeleteUserRegistryPayload struct {
	UserRegistry []*UserRegistry `json:"userRegistry"`
	Msg          *string         `json:"msg"`
	NumUids      *int            `json:"numUids"`
}

type DomainFederation struct {
	ID               string    `json:"id"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
	Domain           string    `json:"domain"`
	Description      string    `json:"description"`
	Keys             []string  `json:"keys"`
	ServiceEndpoints []string  `json:"serviceEndpoints"`
	AllowedList      []string  `json:"allowedList"`
	Status           int       `json:"status"`
}

type DomainFederationFilter struct {
	ID     []string                `json:"id"`
	Domain *StringHashFilter       `json:"domain"`
	And    *DomainFederationFilter `json:"and"`
	Or     *DomainFederationFilter `json:"or"`
	Not    *DomainFederationFilter `json:"not"`
}

type DomainFederationOrder struct {
	Asc  *DomainFederationOrderable `json:"asc"`
	Desc *DomainFederationOrderable `json:"desc"`
	Then *DomainFederationOrder     `json:"then"`
}

type DomainFederationPatch struct {
	CreatedAt        *time.Time `json:"createdAt"`
	UpdatedAt        *time.Time `json:"updatedAt"`
	Description      *string    `json:"description"`
	Keys             []string   `json:"keys"`
	ServiceEndpoints []string   `json:"serviceEndpoints"`
	AllowedList      []string   `json:"allowedList"`
	Status           *int       `json:"status"`
}

type DomainFederationRef struct {
	ID               *string    `json:"id"`
	CreatedAt        *time.Time `json:"createdAt"`
	UpdatedAt        *time.Time `json:"updatedAt"`
	Domain           *string    `json:"domain"`
	Description      *string    `json:"description"`
	Keys             []string   `json:"keys"`
	ServiceEndpoints []string   `json:"serviceEndpoints"`
	AllowedList      []string   `json:"allowedList"`
	Status           *int       `json:"status"`
}

type FloatFilter struct {
	Eq *float64 `json:"eq"`
	Le *float64 `json:"le"`
	Lt *float64 `json:"lt"`
	Ge *float64 `json:"ge"`
	Gt *float64 `json:"gt"`
}

type IntFilter struct {
	Eq *int `json:"eq"`
	Le *int `json:"le"`
	Lt *int `json:"lt"`
	Ge *int `json:"ge"`
	Gt *int `json:"gt"`
}

type ServiceRegistry struct {
	ID               string                       `json:"id"`
	CreatedAt        time.Time                    `json:"createdAt"`
	UpdatedAt        time.Time                    `json:"updatedAt"`
	SubjectID        string                       `json:"subjectId"`
	SubjectType      string                       `json:"subjectType"`
	Description      string                       `json:"description"`
	Keys             []string                     `json:"keys"`
	KeysUpdatedAt    time.Time                    `json:"keysUpdatedAt"`
	Status           int                          `json:"status"`
	ServiceEndpoints []string                     `json:"serviceEndpoints"`
	Permissions      []*ServiceRegistryPermission `json:"permissions"`
	Uk               string                       `json:"uk"`
}

type ServiceRegistryFilter struct {
	ID        []string               `json:"id"`
	SubjectID *StringHashFilter      `json:"subjectId"`
	Status    *IntFilter             `json:"status"`
	Uk        *StringHashFilter      `json:"uk"`
	And       *ServiceRegistryFilter `json:"and"`
	Or        *ServiceRegistryFilter `json:"or"`
	Not       *ServiceRegistryFilter `json:"not"`
}

type ServiceRegistryOrder struct {
	Asc  *ServiceRegistryOrderable `json:"asc"`
	Desc *ServiceRegistryOrderable `json:"desc"`
	Then *ServiceRegistryOrder     `json:"then"`
}

type ServiceRegistryPatch struct {
	CreatedAt        *time.Time                      `json:"createdAt"`
	UpdatedAt        *time.Time                      `json:"updatedAt"`
	SubjectID        *string                         `json:"subjectId"`
	SubjectType      *string                         `json:"subjectType"`
	Description      *string                         `json:"description"`
	Keys             []string                        `json:"keys"`
	KeysUpdatedAt    *time.Time                      `json:"keysUpdatedAt"`
	Status           *int                            `json:"status"`
	ServiceEndpoints []string                        `json:"serviceEndpoints"`
	Permissions      []*ServiceRegistryPermissionRef `json:"permissions"`
}

type ServiceRegistryPermission struct {
	ID         string           `json:"id"`
	CreatedAt  time.Time        `json:"createdAt"`
	UpdatedAt  time.Time        `json:"updatedAt"`
	Resource   string           `json:"resource"`
	Operations []string         `json:"operations"`
	Extensions []string         `json:"extensions"`
	Registry   *ServiceRegistry `json:"registry"`
	Uk         string           `json:"uk"`
}

type ServiceRegistryPermissionFilter struct {
	ID  []string                         `json:"id"`
	Uk  *StringHashFilter                `json:"uk"`
	And *ServiceRegistryPermissionFilter `json:"and"`
	Or  *ServiceRegistryPermissionFilter `json:"or"`
	Not *ServiceRegistryPermissionFilter `json:"not"`
}

type ServiceRegistryPermissionOrder struct {
	Asc  *ServiceRegistryPermissionOrderable `json:"asc"`
	Desc *ServiceRegistryPermissionOrderable `json:"desc"`
	Then *ServiceRegistryPermissionOrder     `json:"then"`
}

type ServiceRegistryPermissionPatch struct {
	CreatedAt  *time.Time          `json:"createdAt"`
	UpdatedAt  *time.Time          `json:"updatedAt"`
	Resource   *string             `json:"resource"`
	Operations []string            `json:"operations"`
	Extensions []string            `json:"extensions"`
	Registry   *ServiceRegistryRef `json:"registry"`
}

type ServiceRegistryPermissionRef struct {
	ID         *string             `json:"id"`
	CreatedAt  *time.Time          `json:"createdAt"`
	UpdatedAt  *time.Time          `json:"updatedAt"`
	Resource   *string             `json:"resource"`
	Operations []string            `json:"operations"`
	Extensions []string            `json:"extensions"`
	Registry   *ServiceRegistryRef `json:"registry"`
	Uk         *string             `json:"uk"`
}

type ServiceRegistryRef struct {
	ID               *string                         `json:"id"`
	CreatedAt        *time.Time                      `json:"createdAt"`
	UpdatedAt        *time.Time                      `json:"updatedAt"`
	SubjectID        *string                         `json:"subjectId"`
	SubjectType      *string                         `json:"subjectType"`
	Description      *string                         `json:"description"`
	Keys             []string                        `json:"keys"`
	KeysUpdatedAt    *time.Time                      `json:"keysUpdatedAt"`
	Status           *int                            `json:"status"`
	ServiceEndpoints []string                        `json:"serviceEndpoints"`
	Permissions      []*ServiceRegistryPermissionRef `json:"permissions"`
	Uk               *string                         `json:"uk"`
}

type StringExactFilter struct {
	Eq *string `json:"eq"`
	Le *string `json:"le"`
	Lt *string `json:"lt"`
	Ge *string `json:"ge"`
	Gt *string `json:"gt"`
}

type StringFullTextFilter struct {
	Alloftext *string `json:"alloftext"`
	Anyoftext *string `json:"anyoftext"`
}

type StringHashFilter struct {
	Eq *string `json:"eq"`
}

type StringRegExpFilter struct {
	Regexp *string `json:"regexp"`
}

type StringTermFilter struct {
	Allofterms *string `json:"allofterms"`
	Anyofterms *string `json:"anyofterms"`
}

type UpdateDomainFederationInput struct {
	Filter *DomainFederationFilter `json:"filter"`
	Set    *DomainFederationPatch  `json:"set"`
	Remove *DomainFederationPatch  `json:"remove"`
}

type UpdateDomainFederationPayload struct {
	DomainFederation []*DomainFederation `json:"domainFederation"`
	NumUids          *int                `json:"numUids"`
}

type UpdateServiceRegistryInput struct {
	Filter *ServiceRegistryFilter `json:"filter"`
	Set    *ServiceRegistryPatch  `json:"set"`
	Remove *ServiceRegistryPatch  `json:"remove"`
}

type UpdateServiceRegistryPayload struct {
	ServiceRegistry []*ServiceRegistry `json:"serviceRegistry"`
	NumUids         *int               `json:"numUids"`
}

type UpdateServiceRegistryPermissionInput struct {
	Filter *ServiceRegistryPermissionFilter `json:"filter"`
	Set    *ServiceRegistryPermissionPatch  `json:"set"`
	Remove *ServiceRegistryPermissionPatch  `json:"remove"`
}

type UpdateServiceRegistryPermissionPayload struct {
	ServiceRegistryPermission []*ServiceRegistryPermission `json:"serviceRegistryPermission"`
	NumUids                   *int                         `json:"numUids"`
}

type UpdateUserRegistryBundleInput struct {
	Filter *UserRegistryBundleFilter `json:"filter"`
	Set    *UserRegistryBundlePatch  `json:"set"`
	Remove *UserRegistryBundlePatch  `json:"remove"`
}

type UpdateUserRegistryBundlePayload struct {
	UserRegistryBundle []*UserRegistryBundle `json:"userRegistryBundle"`
	NumUids            *int                  `json:"numUids"`
}

type UpdateUserRegistryInput struct {
	Filter *UserRegistryFilter `json:"filter"`
	Set    *UserRegistryPatch  `json:"set"`
	Remove *UserRegistryPatch  `json:"remove"`
}

type UpdateUserRegistryPayload struct {
	UserRegistry []*UserRegistry `json:"userRegistry"`
	NumUids      *int            `json:"numUids"`
}

type UserRegistry struct {
	ID            string                `json:"id"`
	CreatedAt     time.Time             `json:"createdAt"`
	UpdatedAt     time.Time             `json:"updatedAt"`
	SubjectID     string                `json:"subjectId"`
	SubjectType   string                `json:"subjectType"`
	Description   string                `json:"description"`
	Keys          []string              `json:"keys"`
	KeysUpdatedAt time.Time             `json:"keysUpdatedAt"`
	Status        int                   `json:"status"`
	ReleaseID     string                `json:"releaseId"`
	Bundles       []*UserRegistryBundle `json:"bundles"`
	Uk            string                `json:"uk"`
}

type UserRegistryBundle struct {
	ID        string           `json:"id"`
	CreatedAt time.Time        `json:"createdAt"`
	UpdatedAt time.Time        `json:"updatedAt"`
	Provider  *ServiceRegistry `json:"provider"`
	BundleID  string           `json:"bundleId"`
	Extension string           `json:"extension"`
	Registry  *UserRegistry    `json:"registry"`
	Uk        string           `json:"uk"`
}

type UserRegistryBundleFilter struct {
	ID       []string                  `json:"id"`
	BundleID *StringHashFilter         `json:"bundleId"`
	Uk       *StringHashFilter         `json:"uk"`
	And      *UserRegistryBundleFilter `json:"and"`
	Or       *UserRegistryBundleFilter `json:"or"`
	Not      *UserRegistryBundleFilter `json:"not"`
}

type UserRegistryBundleOrder struct {
	Asc  *UserRegistryBundleOrderable `json:"asc"`
	Desc *UserRegistryBundleOrderable `json:"desc"`
	Then *UserRegistryBundleOrder     `json:"then"`
}

type UserRegistryBundlePatch struct {
	CreatedAt *time.Time          `json:"createdAt"`
	UpdatedAt *time.Time          `json:"updatedAt"`
	Provider  *ServiceRegistryRef `json:"provider"`
	BundleID  *string             `json:"bundleId"`
	Extension *string             `json:"extension"`
	Registry  *UserRegistryRef    `json:"registry"`
}

type UserRegistryBundleRef struct {
	ID        *string             `json:"id"`
	CreatedAt *time.Time          `json:"createdAt"`
	UpdatedAt *time.Time          `json:"updatedAt"`
	Provider  *ServiceRegistryRef `json:"provider"`
	BundleID  *string             `json:"bundleId"`
	Extension *string             `json:"extension"`
	Registry  *UserRegistryRef    `json:"registry"`
	Uk        *string             `json:"uk"`
}

type UserRegistryFilter struct {
	ID        []string            `json:"id"`
	CreatedAt *DateTimeFilter     `json:"createdAt"`
	SubjectID *StringHashFilter   `json:"subjectId"`
	Status    *IntFilter          `json:"status"`
	Uk        *StringHashFilter   `json:"uk"`
	And       *UserRegistryFilter `json:"and"`
	Or        *UserRegistryFilter `json:"or"`
	Not       *UserRegistryFilter `json:"not"`
}

type UserRegistryOrder struct {
	Asc  *UserRegistryOrderable `json:"asc"`
	Desc *UserRegistryOrderable `json:"desc"`
	Then *UserRegistryOrder     `json:"then"`
}

type UserRegistryPatch struct {
	CreatedAt     *time.Time               `json:"createdAt"`
	UpdatedAt     *time.Time               `json:"updatedAt"`
	SubjectID     *string                  `json:"subjectId"`
	SubjectType   *string                  `json:"subjectType"`
	Description   *string                  `json:"description"`
	Keys          []string                 `json:"keys"`
	KeysUpdatedAt *time.Time               `json:"keysUpdatedAt"`
	Status        *int                     `json:"status"`
	ReleaseID     *string                  `json:"releaseId"`
	Bundles       []*UserRegistryBundleRef `json:"bundles"`
}

type UserRegistryRef struct {
	ID            *string                  `json:"id"`
	CreatedAt     *time.Time               `json:"createdAt"`
	UpdatedAt     *time.Time               `json:"updatedAt"`
	SubjectID     *string                  `json:"subjectId"`
	SubjectType   *string                  `json:"subjectType"`
	Description   *string                  `json:"description"`
	Keys          []string                 `json:"keys"`
	KeysUpdatedAt *time.Time               `json:"keysUpdatedAt"`
	Status        *int                     `json:"status"`
	ReleaseID     *string                  `json:"releaseId"`
	Bundles       []*UserRegistryBundleRef `json:"bundles"`
	Uk            *string                  `json:"uk"`
}

type DgraphIndex string

const (
	DgraphIndexInt      DgraphIndex = "int"
	DgraphIndexFloat    DgraphIndex = "float"
	DgraphIndexBool     DgraphIndex = "bool"
	DgraphIndexHash     DgraphIndex = "hash"
	DgraphIndexExact    DgraphIndex = "exact"
	DgraphIndexTerm     DgraphIndex = "term"
	DgraphIndexFulltext DgraphIndex = "fulltext"
	DgraphIndexTrigram  DgraphIndex = "trigram"
	DgraphIndexRegexp   DgraphIndex = "regexp"
	DgraphIndexYear     DgraphIndex = "year"
	DgraphIndexMonth    DgraphIndex = "month"
	DgraphIndexDay      DgraphIndex = "day"
	DgraphIndexHour     DgraphIndex = "hour"
)

var AllDgraphIndex = []DgraphIndex{
	DgraphIndexInt,
	DgraphIndexFloat,
	DgraphIndexBool,
	DgraphIndexHash,
	DgraphIndexExact,
	DgraphIndexTerm,
	DgraphIndexFulltext,
	DgraphIndexTrigram,
	DgraphIndexRegexp,
	DgraphIndexYear,
	DgraphIndexMonth,
	DgraphIndexDay,
	DgraphIndexHour,
}

func (e DgraphIndex) IsValid() bool {
	switch e {
	case DgraphIndexInt, DgraphIndexFloat, DgraphIndexBool, DgraphIndexHash, DgraphIndexExact, DgraphIndexTerm, DgraphIndexFulltext, DgraphIndexTrigram, DgraphIndexRegexp, DgraphIndexYear, DgraphIndexMonth, DgraphIndexDay, DgraphIndexHour:
		return true
	}
	return false
}

func (e DgraphIndex) String() string {
	return string(e)
}

func (e *DgraphIndex) UnmarshalGQL(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("enums must be strings")
	}

	*e = DgraphIndex(str)
	if !e.IsValid() {
		return fmt.Errorf("%s is not a valid DgraphIndex", str)
	}
	return nil
}

func (e DgraphIndex) MarshalGQL(w io.Writer) {
	fmt.Fprint(w, strconv.Quote(e.String()))
}

type DomainFederationOrderable string

const (
	DomainFederationOrderableCreatedAt        DomainFederationOrderable = "createdAt"
	DomainFederationOrderableUpdatedAt        DomainFederationOrderable = "updatedAt"
	DomainFederationOrderableDomain           DomainFederationOrderable = "domain"
	DomainFederationOrderableDescription      DomainFederationOrderable = "description"
	DomainFederationOrderableKeys             DomainFederationOrderable = "keys"
	DomainFederationOrderableServiceEndpoints DomainFederationOrderable = "serviceEndpoints"
	DomainFederationOrderableAllowedList      DomainFederationOrderable = "allowedList"
	DomainFederationOrderableStatus           DomainFederationOrderable = "status"
)

var AllDomainFederationOrderable = []DomainFederationOrderable{
	DomainFederationOrderableCreatedAt,
	DomainFederationOrderableUpdatedAt,
	DomainFederationOrderableDomain,
	DomainFederationOrderableDescription,
	DomainFederationOrderableKeys,
	DomainFederationOrderableServiceEndpoints,
	DomainFederationOrderableAllowedList,
	DomainFederationOrderableStatus,
}

func (e DomainFederationOrderable) IsValid() bool {
	switch e {
	case DomainFederationOrderableCreatedAt, DomainFederationOrderableUpdatedAt, DomainFederationOrderableDomain, DomainFederationOrderableDescription, DomainFederationOrderableKeys, DomainFederationOrderableServiceEndpoints, DomainFederationOrderableAllowedList, DomainFederationOrderableStatus:
		return true
	}
	return false
}

func (e DomainFederationOrderable) String() string {
	return string(e)
}

func (e *DomainFederationOrderable) UnmarshalGQL(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("enums must be strings")
	}

	*e = DomainFederationOrderable(str)
	if !e.IsValid() {
		return fmt.Errorf("%s is not a valid DomainFederationOrderable", str)
	}
	return nil
}

func (e DomainFederationOrderable) MarshalGQL(w io.Writer) {
	fmt.Fprint(w, strconv.Quote(e.String()))
}

type HTTPMethod string

const (
	HTTPMethodGet    HTTPMethod = "GET"
	HTTPMethodPost   HTTPMethod = "POST"
	HTTPMethodPut    HTTPMethod = "PUT"
	HTTPMethodPatch  HTTPMethod = "PATCH"
	HTTPMethodDelete HTTPMethod = "DELETE"
)

var AllHTTPMethod = []HTTPMethod{
	HTTPMethodGet,
	HTTPMethodPost,
	HTTPMethodPut,
	HTTPMethodPatch,
	HTTPMethodDelete,
}

func (e HTTPMethod) IsValid() bool {
	switch e {
	case HTTPMethodGet, HTTPMethodPost, HTTPMethodPut, HTTPMethodPatch, HTTPMethodDelete:
		return true
	}
	return false
}

func (e HTTPMethod) String() string {
	return string(e)
}

func (e *HTTPMethod) UnmarshalGQL(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("enums must be strings")
	}

	*e = HTTPMethod(str)
	if !e.IsValid() {
		return fmt.Errorf("%s is not a valid HTTPMethod", str)
	}
	return nil
}

func (e HTTPMethod) MarshalGQL(w io.Writer) {
	fmt.Fprint(w, strconv.Quote(e.String()))
}

type Mode string

const (
	ModeBatch  Mode = "BATCH"
	ModeSingle Mode = "SINGLE"
)

var AllMode = []Mode{
	ModeBatch,
	ModeSingle,
}

func (e Mode) IsValid() bool {
	switch e {
	case ModeBatch, ModeSingle:
		return true
	}
	return false
}

func (e Mode) String() string {
	return string(e)
}

func (e *Mode) UnmarshalGQL(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("enums must be strings")
	}

	*e = Mode(str)
	if !e.IsValid() {
		return fmt.Errorf("%s is not a valid Mode", str)
	}
	return nil
}

func (e Mode) MarshalGQL(w io.Writer) {
	fmt.Fprint(w, strconv.Quote(e.String()))
}

type ServiceRegistryOrderable string

const (
	ServiceRegistryOrderableCreatedAt        ServiceRegistryOrderable = "createdAt"
	ServiceRegistryOrderableUpdatedAt        ServiceRegistryOrderable = "updatedAt"
	ServiceRegistryOrderableSubjectID        ServiceRegistryOrderable = "subjectId"
	ServiceRegistryOrderableSubjectType      ServiceRegistryOrderable = "subjectType"
	ServiceRegistryOrderableDescription      ServiceRegistryOrderable = "description"
	ServiceRegistryOrderableKeys             ServiceRegistryOrderable = "keys"
	ServiceRegistryOrderableKeysUpdatedAt    ServiceRegistryOrderable = "keysUpdatedAt"
	ServiceRegistryOrderableStatus           ServiceRegistryOrderable = "status"
	ServiceRegistryOrderableServiceEndpoints ServiceRegistryOrderable = "serviceEndpoints"
	ServiceRegistryOrderableUk               ServiceRegistryOrderable = "uk"
)

var AllServiceRegistryOrderable = []ServiceRegistryOrderable{
	ServiceRegistryOrderableCreatedAt,
	ServiceRegistryOrderableUpdatedAt,
	ServiceRegistryOrderableSubjectID,
	ServiceRegistryOrderableSubjectType,
	ServiceRegistryOrderableDescription,
	ServiceRegistryOrderableKeys,
	ServiceRegistryOrderableKeysUpdatedAt,
	ServiceRegistryOrderableStatus,
	ServiceRegistryOrderableServiceEndpoints,
	ServiceRegistryOrderableUk,
}

func (e ServiceRegistryOrderable) IsValid() bool {
	switch e {
	case ServiceRegistryOrderableCreatedAt, ServiceRegistryOrderableUpdatedAt, ServiceRegistryOrderableSubjectID, ServiceRegistryOrderableSubjectType, ServiceRegistryOrderableDescription, ServiceRegistryOrderableKeys, ServiceRegistryOrderableKeysUpdatedAt, ServiceRegistryOrderableStatus, ServiceRegistryOrderableServiceEndpoints, ServiceRegistryOrderableUk:
		return true
	}
	return false
}

func (e ServiceRegistryOrderable) String() string {
	return string(e)
}

func (e *ServiceRegistryOrderable) UnmarshalGQL(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("enums must be strings")
	}

	*e = ServiceRegistryOrderable(str)
	if !e.IsValid() {
		return fmt.Errorf("%s is not a valid ServiceRegistryOrderable", str)
	}
	return nil
}

func (e ServiceRegistryOrderable) MarshalGQL(w io.Writer) {
	fmt.Fprint(w, strconv.Quote(e.String()))
}

type ServiceRegistryPermissionOrderable string

const (
	ServiceRegistryPermissionOrderableCreatedAt  ServiceRegistryPermissionOrderable = "createdAt"
	ServiceRegistryPermissionOrderableUpdatedAt  ServiceRegistryPermissionOrderable = "updatedAt"
	ServiceRegistryPermissionOrderableResource   ServiceRegistryPermissionOrderable = "resource"
	ServiceRegistryPermissionOrderableOperations ServiceRegistryPermissionOrderable = "operations"
	ServiceRegistryPermissionOrderableExtensions ServiceRegistryPermissionOrderable = "extensions"
	ServiceRegistryPermissionOrderableUk         ServiceRegistryPermissionOrderable = "uk"
)

var AllServiceRegistryPermissionOrderable = []ServiceRegistryPermissionOrderable{
	ServiceRegistryPermissionOrderableCreatedAt,
	ServiceRegistryPermissionOrderableUpdatedAt,
	ServiceRegistryPermissionOrderableResource,
	ServiceRegistryPermissionOrderableOperations,
	ServiceRegistryPermissionOrderableExtensions,
	ServiceRegistryPermissionOrderableUk,
}

func (e ServiceRegistryPermissionOrderable) IsValid() bool {
	switch e {
	case ServiceRegistryPermissionOrderableCreatedAt, ServiceRegistryPermissionOrderableUpdatedAt, ServiceRegistryPermissionOrderableResource, ServiceRegistryPermissionOrderableOperations, ServiceRegistryPermissionOrderableExtensions, ServiceRegistryPermissionOrderableUk:
		return true
	}
	return false
}

func (e ServiceRegistryPermissionOrderable) String() string {
	return string(e)
}

func (e *ServiceRegistryPermissionOrderable) UnmarshalGQL(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("enums must be strings")
	}

	*e = ServiceRegistryPermissionOrderable(str)
	if !e.IsValid() {
		return fmt.Errorf("%s is not a valid ServiceRegistryPermissionOrderable", str)
	}
	return nil
}

func (e ServiceRegistryPermissionOrderable) MarshalGQL(w io.Writer) {
	fmt.Fprint(w, strconv.Quote(e.String()))
}

type UserRegistryBundleOrderable string

const (
	UserRegistryBundleOrderableCreatedAt UserRegistryBundleOrderable = "createdAt"
	UserRegistryBundleOrderableUpdatedAt UserRegistryBundleOrderable = "updatedAt"
	UserRegistryBundleOrderableBundleID  UserRegistryBundleOrderable = "bundleId"
	UserRegistryBundleOrderableExtension UserRegistryBundleOrderable = "extension"
	UserRegistryBundleOrderableUk        UserRegistryBundleOrderable = "uk"
)

var AllUserRegistryBundleOrderable = []UserRegistryBundleOrderable{
	UserRegistryBundleOrderableCreatedAt,
	UserRegistryBundleOrderableUpdatedAt,
	UserRegistryBundleOrderableBundleID,
	UserRegistryBundleOrderableExtension,
	UserRegistryBundleOrderableUk,
}

func (e UserRegistryBundleOrderable) IsValid() bool {
	switch e {
	case UserRegistryBundleOrderableCreatedAt, UserRegistryBundleOrderableUpdatedAt, UserRegistryBundleOrderableBundleID, UserRegistryBundleOrderableExtension, UserRegistryBundleOrderableUk:
		return true
	}
	return false
}

func (e UserRegistryBundleOrderable) String() string {
	return string(e)
}

func (e *UserRegistryBundleOrderable) UnmarshalGQL(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("enums must be strings")
	}

	*e = UserRegistryBundleOrderable(str)
	if !e.IsValid() {
		return fmt.Errorf("%s is not a valid UserRegistryBundleOrderable", str)
	}
	return nil
}

func (e UserRegistryBundleOrderable) MarshalGQL(w io.Writer) {
	fmt.Fprint(w, strconv.Quote(e.String()))
}

type UserRegistryOrderable string

const (
	UserRegistryOrderableCreatedAt     UserRegistryOrderable = "createdAt"
	UserRegistryOrderableUpdatedAt     UserRegistryOrderable = "updatedAt"
	UserRegistryOrderableSubjectID     UserRegistryOrderable = "subjectId"
	UserRegistryOrderableSubjectType   UserRegistryOrderable = "subjectType"
	UserRegistryOrderableDescription   UserRegistryOrderable = "description"
	UserRegistryOrderableKeys          UserRegistryOrderable = "keys"
	UserRegistryOrderableKeysUpdatedAt UserRegistryOrderable = "keysUpdatedAt"
	UserRegistryOrderableStatus        UserRegistryOrderable = "status"
	UserRegistryOrderableReleaseID     UserRegistryOrderable = "releaseId"
	UserRegistryOrderableUk            UserRegistryOrderable = "uk"
)

var AllUserRegistryOrderable = []UserRegistryOrderable{
	UserRegistryOrderableCreatedAt,
	UserRegistryOrderableUpdatedAt,
	UserRegistryOrderableSubjectID,
	UserRegistryOrderableSubjectType,
	UserRegistryOrderableDescription,
	UserRegistryOrderableKeys,
	UserRegistryOrderableKeysUpdatedAt,
	UserRegistryOrderableStatus,
	UserRegistryOrderableReleaseID,
	UserRegistryOrderableUk,
}

func (e UserRegistryOrderable) IsValid() bool {
	switch e {
	case UserRegistryOrderableCreatedAt, UserRegistryOrderableUpdatedAt, UserRegistryOrderableSubjectID, UserRegistryOrderableSubjectType, UserRegistryOrderableDescription, UserRegistryOrderableKeys, UserRegistryOrderableKeysUpdatedAt, UserRegistryOrderableStatus, UserRegistryOrderableReleaseID, UserRegistryOrderableUk:
		return true
	}
	return false
}

func (e UserRegistryOrderable) String() string {
	return string(e)
}

func (e *UserRegistryOrderable) UnmarshalGQL(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("enums must be strings")
	}

	*e = UserRegistryOrderable(str)
	if !e.IsValid() {
		return fmt.Errorf("%s is not a valid UserRegistryOrderable", str)
	}
	return nil
}

func (e UserRegistryOrderable) MarshalGQL(w io.Writer) {
	fmt.Fprint(w, strconv.Quote(e.String()))
}
