package rbac

import (
	"encoding/json"
	"strings"
)

// A PermissionConstructor is a function that creates a new Permission
// from the specified action and target strings.
type PermissionConstructor func(action, target string) Permission

// DefaultPermissionConstructors returns a mapping of constructor names to PermissionConstructor functions
// for each of the builtin PermissionConstructors:
//
//	"glob":   NewGlobPermission
//	"regex":  NewRegexPermission
//	"string": NewStringPermission
func DefaultPermissionConstructors() map[string]PermissionConstructor {
	return map[string]PermissionConstructor{
		"glob":   NewGlobPermission,
		"regex":  NewRegexPermission,
		"string": NewStringPermission,
	}
}

// A PermissionTemplate holds information about a permission in templated format.
type PermissionTemplate struct {
	Constructor string `json:"constructor"`
	Action      string `json:"action"`
	Target      string `json:"target"`
}

// A PolicyTemplate holds information about a Role in a templated format.
// This format can be encoded to and from JSON.
type PolicyTemplate struct {
	RoleID              string               `json:"role_id"`
	PermissionTemplates []PermissionTemplate `json:"permissions"`
	constructors        map[string]PermissionConstructor
}

// NewPolicyTemplate generates a new PolicyTemplate with the specified roleID and default constructors.
func NewPolicyTemplate(roleID string) *PolicyTemplate {
	return &PolicyTemplate{
		RoleID:              roleID,
		PermissionTemplates: []PermissionTemplate{},
		constructors:        DefaultPermissionConstructors(),
	}
}

// AddPermission adds a new PermissionTemplate to p.PermissionTemplates.
func (p *PolicyTemplate) AddPermission(constructor, action, target string) {
	p.PermissionTemplates = append(p.PermissionTemplates, PermissionTemplate{constructor, action, target})
}

// SetConstructor updates the mapping of a constructor name to a PermissionConstructor.
// If a mapping for the specified same name already exists, it will be overwritten.
func (p *PolicyTemplate) SetConstructor(name string, constructor PermissionConstructor) {
	p.constructors[name] = constructor
}

// DeleteConstructor will remove the constructor mapping at the specified name if it exists.
func (p *PolicyTemplate) DeleteConstructor(name string) {
	delete(p.constructors, name)
}

// Role converts the PolicyTemplate to a Role.
// Replacer can be used to replace variables within the Action and Target fields in the PermissionTemplates.
// Use GlobPermission as default if a PermissionTemplate.Constructor does not have a corresponding PermissionConstructor.
func (p *PolicyTemplate) Role(replacer *strings.Replacer) *Role {
	role := &Role{
		RoleID:      p.RoleID,
		Permissions: make(Permissions, len(p.PermissionTemplates)),
	}

	for i, permissionTemplate := range p.PermissionTemplates {
		constructor, ok := p.constructors[permissionTemplate.Constructor]
		if !ok {
			constructor = NewGlobPermission
		}

		action := permissionTemplate.Action
		target := permissionTemplate.Target
		if replacer != nil {
			action = replacer.Replace(action)
			target = replacer.Replace(target)
		}
		role.Permissions[i] = constructor(action, target)
	}

	return role
}

// UnmarshalJSON allows a *PolicyTemplate to implement the json.Unmarshaler interface.
// We do this to set the default constructors on p after the unmarshalling.
func (p *PolicyTemplate) UnmarshalJSON(data []byte) error {
	type Alias PolicyTemplate
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(p),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	p.constructors = DefaultPermissionConstructors()
	return nil
}
