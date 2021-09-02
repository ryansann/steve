package accesscontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	v1 "github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
			hash := getAccessSetHash(user, as)
			fmt.Printf("CACHE HIT | user: %s, time: %v, hash: %s\n", user.GetName(), time.Now().Unix(), hash)
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

	hash := getAccessSetHash(user, result)
	fmt.Printf("CACHE MISS | user: %s, time: %v, hash: %s\n", user.GetName(), time.Now().Unix(), hash)
	return result
}

func (l *AccessStore) CacheKey(user user.Info) string {
	d := sha256.New()

	l.users.addRolesToHash(d, user.GetName())

	groupBase := user.GetGroups()
	groups := make([]string, len(groupBase))
	copy(groups, groupBase)
	sort.Strings(groups)
	for _, group := range groups {
		l.groups.addRolesToHash(d, group)
	}

	return hex.EncodeToString(d.Sum(nil))
}

type AccessSetPretty struct {
	ID  string     `json:"id"`
	Set []SetEntry `json:"set"`
}

type SetEntry struct {
	Key               SetKey            `json:"key"`
	ResourceAccessSet ResourceAccessSet `json:"resourceAccessSet"`
}

type ResourceAccessSet []Access

type SetKey struct {
	Verb string               `json:"verb"`
	GR   schema.GroupResource `json:"groupResource"`
}

func getAccessSetHash(user user.Info, s *AccessSet) string {
	as := &AccessSetPretty{
		ID:  s.ID,
		Set: []SetEntry{},
	}
	for k, v := range s.set {
		setKey := SetKey{
			Verb: k.verb,
			GR:   k.gr,
		}
		var l []Access
		for k2 := range v {
			l = append(l, k2)
		}
		sort.Slice(l, func(i, j int) bool {
			k1 := l[i].Namespace + l[j].ResourceName
			k2 := l[j].Namespace + l[j].ResourceName
			return k1 < k2
		})
		setEntry := SetEntry{
			Key:               setKey,
			ResourceAccessSet: l,
		}
		as.Set = append(as.Set, setEntry)
	}
	sort.Slice(as.Set, func(i, j int) bool {
		k1 := as.Set[i].Key.Verb + as.Set[i].Key.GR.Group + as.Set[i].Key.GR.Resource
		k2 := as.Set[j].Key.Verb + as.Set[j].Key.GR.Group + as.Set[j].Key.GR.Resource
		return k1 < k2
	})
	byts, err := json.Marshal(as)
	if err != nil {
		fmt.Println(err)
	}
	d := sha256.New()
	d.Write(byts)
	hash := hex.EncodeToString(d.Sum(nil))
	return hash
}
