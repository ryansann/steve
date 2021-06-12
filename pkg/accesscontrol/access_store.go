package accesscontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
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
	// mtx guards userKeys
	mtx      *sync.Mutex
	userKeys map[string]string
}

type roleKey struct {
	namespace string
	name      string
}

const (
	cacheSize = 50
)

func NewAccessStore(ctx context.Context, cacheResults bool, rbac v1.Interface) *AccessStore {
	revisions := newRoleRevision(ctx, rbac)
	as := &AccessStore{
		users:  newPolicyRuleIndex(true, revisions, rbac),
		groups: newPolicyRuleIndex(false, revisions, rbac),
	}
	if cacheResults {
		as.cache = cache.NewLRUExpireCache(cacheSize)
		as.mtx = &sync.Mutex{}
		as.userKeys = make(map[string]string, cacheSize)
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
			return as
		}
	}

	result := l.users.get(user.GetName())
	for _, group := range user.GetGroups() {
		result.Merge(l.groups.get(group))
	}

	if l.cache != nil {
		result.ID = cacheKey
		l.mtx.Lock()
		defer l.mtx.Unlock()
		if prevKey, ok := l.userKeys[user.GetName()]; ok && prevKey != cacheKey {
			l.cache.Remove(prevKey)
		}
		l.userKeys[user.GetName()] = cacheKey
		l.cache.Add(cacheKey, result, 24*time.Hour)
	}

	return result
}

func (l *AccessStore) CacheKey(user user.Info) string {
	d := sha256.New()

	l.users.addRolesToHash(d, user.GetName())

	groupBase := user.GetGroups()
	groups := make([]string, 0, len(groupBase))
	copy(groups, groupBase)

	sort.Strings(groups)
	for _, group := range user.GetGroups() {
		l.groups.addRolesToHash(d, group)
	}

	return hex.EncodeToString(d.Sum(nil))
}
