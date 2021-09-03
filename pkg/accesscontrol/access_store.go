package accesscontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/authentication/user"
)

type AccessSetLookup interface {
	AccessFor(user user.Info) *AccessSet
}

type AccessStore struct {
	users  *policyRuleIndex
	groups *policyRuleIndex
	cache  *cache.LRUExpireCache
}

type roleKey struct {
	namespace string
	name      string
}

func NewAccessStore(ctx context.Context, cacheResults bool, rbac v1.Interface) *AccessStore {
	revisions := newRoleRevision(ctx, rbac)
	as := &AccessStore{
		users:  newPolicyRuleIndex(true, revisions, rbac),
		groups: newPolicyRuleIndex(false, revisions, rbac),
	}
	if cacheResults {
		as.cache = cache.NewLRUExpireCache(50)
	}
	return as
}

func (l *AccessStore) AccessFor(user user.Info) *AccessSet {
	var cacheKey string
	if l.cache != nil {
		cacheKey = l.CacheKey(user)
		val, ok := l.cache.Get(cacheKey)
		if ok {
			as, _ := val.(*AccessSet)
			hash := getHash(as)
			fmt.Printf("CACHE HIT | user: %s, time: %v, key: %s, hash: %s\n", user.GetName(), time.Now().Unix(), cacheKey, hash)
			return as
		}
	}

	result := l.users.get(user.GetName())
	for _, group := range user.GetGroups() {
		result.Merge(l.groups.get(group))
	}

	if l.cache != nil {
		result.ID = cacheKey
		l.cache.Add(cacheKey, result, 24*time.Hour)
	}

	hash := getHash(result)
	fmt.Printf("CACHE MISS | user: %s, time: %v, key: %s, hash: %s\n", user.GetName(), time.Now().Unix(), cacheKey, hash)
	return result
}

func (l *AccessStore) CacheKey(user user.Info) string {
	d := sha256.New()

	userRoleInfo := l.users.addRolesToHash(d, user.GetName())
	fmt.Printf("user: %s, roleInfo: %v\n", user.GetName(), userRoleInfo)

	var groupRoleInfo []string
	groupBase := user.GetGroups()
	groups := make([]string, len(groupBase))
	copy(groups, groupBase)
	sort.Strings(groups)
	for _, group := range groups {
		ri := l.groups.addRolesToHash(d, group)
		groupRoleInfo = append(groupRoleInfo, ri...)
	}

	fmt.Printf("user: %s, groups: %v, groupRoleInfo: %v\n", user.GetName(), user.GetGroups(), groupRoleInfo)

	return hex.EncodeToString(d.Sum(nil))
}

func getHash(a *AccessSet) string {
	var keys []string
	var accesses []string
	for gvr, as := range a.set {
		s := strings.Join([]string{gvr.gr.Group, gvr.verb, gvr.gr.Resource}, "")
		keys = append(keys, s)
		for access, granted := range as {
			astr := strings.Join([]string{access.Namespace, access.ResourceName, strconv.FormatBool(granted)}, "")
			accesses = append(accesses, astr)
		}
	}
	sort.Strings(keys)
	sort.Strings(accesses)

	ks := strings.Join(keys, "")
	acs := strings.Join(accesses, "")

	d := sha256.New()
	d.Write([]byte(ks))
	d.Write([]byte(acs))
	return hex.EncodeToString(d.Sum(nil))
}
