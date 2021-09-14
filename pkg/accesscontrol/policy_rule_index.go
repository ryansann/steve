package accesscontrol

import (
	"fmt"
	"hash"
	"sort"

	v1 "github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	rbacGroup = "rbac.authorization.k8s.io"
	All       = "*"
)

type policyRuleIndex struct {
	crCache             v1.ClusterRoleCache
	rCache              v1.RoleCache
	crbCache            v1.ClusterRoleBindingCache
	rbCache             v1.RoleBindingCache
	revisions           *roleRevisionIndex
	kind                string
	roleIndexKey        string
	clusterRoleIndexKey string
}

func newPolicyRuleIndex(user bool, revisions *roleRevisionIndex, rbac v1.Interface) *policyRuleIndex {
	key := "Group"
	if user {
		key = "User"
	}
	pi := &policyRuleIndex{
		kind:                key,
		crCache:             rbac.ClusterRole().Cache(),
		rCache:              rbac.Role().Cache(),
		crbCache:            rbac.ClusterRoleBinding().Cache(),
		rbCache:             rbac.RoleBinding().Cache(),
		clusterRoleIndexKey: "crb" + key,
		roleIndexKey:        "rb" + key,
		revisions:           revisions,
	}

	pi.crbCache.AddIndexer(pi.clusterRoleIndexKey, pi.clusterRoleBindingBySubjectIndexer)
	pi.rbCache.AddIndexer(pi.roleIndexKey, pi.roleBindingBySubject)

	return pi
}

func (p *policyRuleIndex) clusterRoleBindingBySubjectIndexer(crb *rbacv1.ClusterRoleBinding) (result []string, err error) {
	for _, subject := range crb.Subjects {
		if subject.APIGroup == rbacGroup && subject.Kind == p.kind && crb.RoleRef.Kind == "ClusterRole" {
			result = append(result, subject.Name)
		} else if subject.APIGroup == "" && p.kind == "User" && subject.Kind == "ServiceAccount" && subject.Namespace != "" && crb.RoleRef.Kind == "ClusterRole" {
			// Index is for Users and this references a service account
			result = append(result, fmt.Sprintf("serviceaccount:%s:%s", subject.Namespace, subject.Name))
		}
	}
	return
}

func (p *policyRuleIndex) roleBindingBySubject(rb *rbacv1.RoleBinding) (result []string, err error) {
	for _, subject := range rb.Subjects {
		if subject.APIGroup == rbacGroup && subject.Kind == p.kind {
			result = append(result, subject.Name)
		} else if subject.APIGroup == "" && p.kind == "User" && subject.Kind == "ServiceAccount" && subject.Namespace != "" {
			// Index is for Users and this references a service account
			result = append(result, fmt.Sprintf("serviceaccount:%s:%s", subject.Namespace, subject.Name))
		}
	}
	return
}

var null = []byte{'\x00'}

func (p *policyRuleIndex) addRolesToHash(digest hash.Hash, subjectName string) (roleInfo []string, crbNames []string, rbNames []string) {
	crbs := p.getClusterRoleBindings(subjectName)
	for _, crb := range crbs {
		name := crb.RoleRef.Name
		revision := p.revisions.roleRevision("", crb.RoleRef.Name)

		roleInfo = append(roleInfo, name+"/"+revision)
		crbNames = append(crbNames, crb.Name)

		digest.Write([]byte(name))
		digest.Write([]byte(revision))
		digest.Write(null)
	}

	rbs := p.getRoleBindings(subjectName)
	for _, rb := range rbs {
		name := rb.RoleRef.Name
		ns := rb.Namespace

		// RoleBindings can bind to either ClusterRoles or Roles
		var revision string
		if rb.RoleRef.Kind == "ClusterRole" {
			revision = p.revisions.roleRevision("", rb.RoleRef.Name)
		} else { // "Role"
			revision = p.revisions.roleRevision(rb.Namespace, rb.RoleRef.Name)
		}

		if ns == "" {
			roleInfo = append(roleInfo, name+"/"+revision)
		} else {
			roleInfo = append(roleInfo, ns+"/"+name+"/"+revision)
		}

		rbNames = append(rbNames, rb.Name)

		digest.Write([]byte(name))
		digest.Write([]byte(ns))
		digest.Write([]byte(revision))
		digest.Write(null)
	}

	return
}

func (p *policyRuleIndex) get(subjectName string) *AccessSet {
	result := &AccessSet{}

	for _, binding := range p.getRoleBindings(subjectName) {
		p.addAccess(result, binding.Namespace, binding.RoleRef)
	}

	for _, binding := range p.getClusterRoleBindings(subjectName) {
		p.addAccess(result, All, binding.RoleRef)
	}

	return result
}

func (p *policyRuleIndex) addAccess(accessSet *AccessSet, namespace string, roleRef rbacv1.RoleRef) {
	for _, rule := range p.getRules(namespace, roleRef) {
		for _, group := range rule.APIGroups {
			for _, resource := range rule.Resources {
				names := rule.ResourceNames
				if len(names) == 0 {
					names = []string{All}
				}
				for _, resourceName := range names {
					for _, verb := range rule.Verbs {
						accessSet.Add(verb,
							schema.GroupResource{
								Group:    group,
								Resource: resource,
							}, Access{
								Namespace:    namespace,
								ResourceName: resourceName,
							})
					}
				}
			}
		}
	}
}

func (p *policyRuleIndex) getRules(namespace string, roleRef rbacv1.RoleRef) []rbacv1.PolicyRule {
	switch roleRef.Kind {
	case "ClusterRole":
		role, err := p.crCache.Get(roleRef.Name)
		if err != nil {
			return nil
		}
		return role.Rules
	case "Role":
		role, err := p.rCache.Get(namespace, roleRef.Name)
		if err != nil {
			return nil
		}
		return role.Rules
	}

	return nil
}

func (p *policyRuleIndex) getClusterRoleBindings(subjectName string) []*rbacv1.ClusterRoleBinding {
	result, err := p.crbCache.GetByIndex(p.clusterRoleIndexKey, subjectName)
	if err != nil {
		return nil
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}

func (p *policyRuleIndex) getRoleBindings(subjectName string) []*rbacv1.RoleBinding {
	result, err := p.rbCache.GetByIndex(p.roleIndexKey, subjectName)
	if err != nil {
		return nil
	}
	sort.Slice(result, func(i, j int) bool {
		return string(result[i].UID) < string(result[j].UID)
	})
	return result
}
