package router

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rancher/apiserver/pkg/urlbuilder"
)

type RouterFunc func(h Handlers) http.Handler

type Handlers struct {
	K8sResource http.Handler
	APIRoot     http.Handler
	K8sProxy    http.Handler
	Next        http.Handler
}

func Routes(h Handlers) http.Handler {
	m := mux.NewRouter()
	m.UseEncodedPath()
	m.StrictSlash(true)
	m.Use(rejectIfBlackListed, urlbuilder.RedirectRewrite)

	m.Path("/").Handler(h.APIRoot).HeadersRegexp("Accepts", ".*json.*")
	m.Path("/{name:v1}").Handler(h.APIRoot)

	m.Path("/v1/{type}").Handler(h.K8sResource)
	m.Path("/v1/{type}/{nameorns}").Queries("link", "{link}").Handler(h.K8sResource)
	m.Path("/v1/{type}/{nameorns}").Queries("action", "{action}").Handler(h.K8sResource)
	m.Path("/v1/{type}/{nameorns}").Handler(h.K8sResource)
	m.Path("/v1/{type}/{namespace}/{name}").Queries("action", "{action}").Handler(h.K8sResource)
	m.Path("/v1/{type}/{namespace}/{name}").Queries("link", "{link}").Handler(h.K8sResource)
	m.Path("/v1/{type}/{namespace}/{name}").Handler(h.K8sResource)
	m.Path("/v1/{type}/{namespace}/{name}/{link}").Handler(h.K8sResource)
	m.Path("/api").Handler(h.K8sProxy) // Can't just prefix this as UI needs /apikeys path
	m.PathPrefix("/api/").Handler(h.K8sProxy)
	m.PathPrefix("/apis").Handler(h.K8sProxy)
	m.PathPrefix("/openapi").Handler(h.K8sProxy)
	m.PathPrefix("/version").Handler(h.K8sProxy)
	m.NotFoundHandler = h.Next

	return m
}

var blackListTypes = []string{
	"management.cattle.io.authconfig",
	"management.cattle.io.catalogtemplate",
	"management.cattle.io.catalog",
	"management.cattle.io.cluster",
	"management.cattle.io.clusterroletemplatebinding",
	"management.cattle.io.feature",
	"management.cattle.io.group",
	"management.cattle.io.kontainerdriver",
	"management.cattle.io.node",
	"management.cattle.io.nodedriver",
	"management.cattle.io.nodepool",
	"management.cattle.io.nodetemplate",
	"management.cattle.io.project",
	"management.cattle.io.projectroletemplatebinding",
	"management.cattle.io.roletemplate",
	"management.cattle.io.setting",
	"management.cattle.io.user",
	"management.cattle.io.token",
	"management.cattle.io.globalrole",
	"management.cattle.io.globalrolebinding",
	"management.cattle.io.podsecuritypolicytemplate",
}

// rejectIfBlackListed is a middleware that rejects requests that have a blacklisted type in their url path
func rejectIfBlackListed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		typ, ok := params["type"]
		if !ok { // admit if there is no type param in the path
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet { // admit get requests
			next.ServeHTTP(w, r)
			return
		}
		for _, t := range blackListTypes {
			if strings.Contains(typ, t) {
				http.Error(w, fmt.Sprintf("routes with type: %s are blacklisted", t), http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
