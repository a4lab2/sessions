package session

import (
	"container/list"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

//Design inspired by database/sql/driver style
//

var provides = make(map[string]Provider)

type Manager struct {
	cookieName  string
	lock        sync.Mutex
	provider    Provider
	maxlifetime int64
}

type Provider interface {
	SessionInit(sid string) (Session, error)
	SessionRead(sid string) (Session, error)
	SessionDestroy(sid string) (Session, error)
	SessionGC(maxLifeTime int64)
}

func NewManager(provideName, cookieName string, maxlifetime int64) (*Manager, error) {

	provider, ok := provides[provideName]
	if !ok {
		return nil, fmt.Errorf("session:unknown provide %q (forgotten import?)", provideName)
	}
	return &Manager{provider: provider, cookieName: cookieName, maxlifetime: maxlifetime}, nil

}

var globalSessions *Manager

func init() {
	globalSessions = NewManager("memory", "gosessionid", 3600)
}

type Session interface {
	Set(key, value interface{}) error
	Get(key interface{}) error
	Delete(key interface{}) error
	SessionID() string
}

func Register(name string, provider Provider) {
	if provider == nil {
		panic("session:Regsiter provider is nil")
	}
	if _, dup := provides[name]; dup {
		panic("session: Register called twice for provider" + name)
	}
	provides[name] = provider
}

func (m *Manager) sessionId() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

func (m *Manager) SessionStart(w http.ResponseWriter, r *http.Request) (session Session) {
	m.lock.Lock()
	defer m.lock.Unlock()
	cookie, err := r.Cookie(m.cookieName)
	if err != nil || cookie.Value == "" {
		sid := m.sessionId()
		session, _ = m.provider.SessionInit(sid)
		cookie := http.Cookie{
			Name:     m.cookieName,
			Value:    url.QueryEscape(sid),
			Path:     "/",
			HttpOnly: true,
			MaxAge:   int(m.maxlifetime)}
		http.SetCookie(w, &cookie)
	} else {

		sid, _ := url.QueryUnescape(cookie.Value)
		session, _ = m.provider.SessionRead(sid)

	}
	return
}

// func login(w http.ResponseWriter, r *http.Request) {
// 	s := globalSessions.SessionStart(w, r)
// 	r.ParseForm()
// 	if r.Method == "GET" {
// 		t, _ := template.ParseFiles("login.gtpl")
// 		w.Header().Set("Content-Type", "text/html")
// 		t.Execute(w, s.Get("username"))
// 	} else {
// 		s.Set("username", r.Form["username"])
// 		http.Redirect(w, r, "/", 302)
// 	}
// }

func (m *Manager) SessionDestroy(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil || cookie.Value == "" {
		return
	} else {
		m.lock.Lock()
		defer m.lock.Unlock()
		m.provider.SessionDestroy(cookie.Value)
		exp := time.Now()
		cookie := http.Cookie{Name: m.cookieName, Path: "/", HttpOnly: true, Expires: exp, MaxAge: -1}
		http.SetCookie(w, &cookie)
	}
}

func init() {
	go globalSessions.GC()
}
func (m *Manager) GC() {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.provider.SessionGC(m.maxlifetime)
	time.AfterFunc(time.Duration(m.maxlifetime), func() { m.GC() })
}

func count(w http.ResponseWriter, r *http.Request) {
	s := globalSessions.SessionStart(w, r)
	createtime := s.Get("createtime")
	if createtime == nil {
		s.Set("createtime", time.Now().Unix())

	} else if (createtime.(int64) + 360) < (time.Now().Unix()) {
		globalSessions.SessionDestroy(w, r)
		s = globalSessions.SessionStart(w, r)
	}
	ct := s.Get("countnum")
	if ct == nil {
		s.Set("countnum", 1)
	} else {
		s.Set("countnum", (ct.(int) + 1))
	}

	t, _ := template.ParseFiles("count.gtpl")
	w.Header().Set("Content-Type", "text/html")
	t.Execute(w, s.Get("countnum"))
}

var pder = &Provider{list: list.New()}
