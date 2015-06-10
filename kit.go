package authkit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/oauth2"
)

const (
	signMethod = "RS256"
	rsaHeader  = "RSA PRIVATE KEY"
)

var (
	arIndex = regexp.MustCompile(`\[\d\]`)
)

// AuthRegistration describes a provider to authenticate against.
type AuthRegistration struct {
	Network        string   `json:"network"`
	ClientID       string   `json:"clientid"`
	ClientSecret   string   `json:"clientsecret"`
	Scopes         []string `json:"scopes"`
	AuthURL        string   `json:"authurl"`
	AccessTokenURL string   `json:"accesstokenurl"`
	UserinfoURLs   []string `json:"userinfo_urls"`
	UserinfoBase   string   `json:"userinfo_base"`
	PathEMail      string   `json:"pathemail"`
	PathID         string   `json:"pathid"`
	PathName       string   `json:"pathname"`
	PathPicture    string   `json:"pathpicture"`
	PathCover      string   `json:"pathcover"`
}

// An Unparsed value is a raw map with the unparsed json contents.
type Unparsed map[string]interface{}

// An AuthUser is a Uid and a Name. The backgroundurl
// and the thumbnailurl are optional an can be empty.
type AuthUser struct {
	Network       string   `json:"network"`
	ID            string   `json:"id"`
	EMail         string   `json:"email"`
	Name          string   `json:"name"`
	BackgroundURL string   `json:"backgroundurl"`
	ThumbnailURL  string   `json:"thumbnail"`
	Fields        Unparsed `json:"fields"`
}

// A Token is a response from a backend provider.
type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
}

// Values are additional values for the JWT token which can be
// filled by the application.
type Values map[string]string

// Extender is a function which must return a expire duration
// for the JWT token. The function also can return a map of (string,string)
// pairs which will be embedded in the JWT token. If this function
// returns an error, the whole authentication fails.
type Extender func(AuthUser, Token) (time.Duration, Values, error)

// Merge merges two extender functions. The duration of the extender
// in the parameter list will be used. The values in the value map
// will be merged so that the values of the given extender will
// overwrite the others.
func (tf Extender) Merge(f Extender) Extender {
	return func(u AuthUser, t Token) (time.Duration, Values, error) {
		// first call original
		od, ov, e := tf(u, t)
		if e != nil {
			return od, ov, e
		}
		// now new one
		nd, nv, e := f(u, t)
		if e != nil {
			return nd, nv, e
		}
		if ov == nil {
			ov = make(Values)
		}
		if nv != nil {
			// if the new finalizer has values, put them in the other value map
			for k, v := range nv {
				ov[k] = v
			}
		}
		return nd, ov, nil
	}
}

// An Authkit stores a map of providers which are identified by a networkname.
type Authkit struct {
	// The Finalizer will be called at the end of the authentication to
	// finalize the JWT token.
	TokenExtender Extender
	providers     map[string]AuthRegistration
	url           string
	key           *rsa.PrivateKey
}

// An AuthContext contains an authenticated user and additional claims
type AuthContext struct {
	User   AuthUser
	Claims Values
}

// An AuthHandler is a callback function with the current authenticated
// user and claims. The claims are all values which are stored
// in the JWT token. You can put your own values with a specific TokenExtender
// function in the Authkit.
type AuthHandler func(ac *AuthContext, w http.ResponseWriter, rq *http.Request)

func defaultExtender(u AuthUser, t Token) (time.Duration, Values, error) {
	dur := 60 * time.Minute
	return dur, nil, nil
}

// New returns a new Authkit with the given url as a prefix
func New(url string) (*Authkit, error) {
	a := &Authkit{}
	a.providers = make(map[string]AuthRegistration)
	if !strings.HasSuffix(url, "/") {
		url = url + "/"
	}
	a.url = url
	a.TokenExtender = defaultExtender
	return a, a.generateKey()
}

// Add will add the given registration to the map of providers. If there
// is already a provider with the same 'Network' name, the old one will
// be overwritten.
func (kit *Authkit) Add(r AuthRegistration) {
	kit.providers[r.Network] = r
}

func (kit *Authkit) generateKey() error {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("cannot create new rsa key: %s", err)
	}
	kit.key = pk
	return nil
}

// DumpKey returns a string representation of the current RSA private key
func (kit *Authkit) DumpKey() string {
	data := pem.Block{Type: rsaHeader, Bytes: x509.MarshalPKCS1PrivateKey(kit.key)}
	return string(pem.EncodeToMemory(&data))
}

// UseKey puts the PEM encoded key from the given reader to the authkit.
func (kit *Authkit) UseKey(r io.Reader) error {
	b, e := ioutil.ReadAll(r)
	if e != nil {
		return fmt.Errorf("cannot read data from key: %s", e)
	}
	blk, _ := pem.Decode(b)
	if blk.Type != rsaHeader {
		return fmt.Errorf("only '%s' supported, but type is '%s'", rsaHeader, blk.Type)
	}
	k, e := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if e != nil {
		return fmt.Errorf("cannot parse the private key: %s", e)
	}
	kit.key = k
	return nil
}

// Handle turns a AuthHandler to a normal HandlerFunc
func (kit *Authkit) Handle(h AuthHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, rq *http.Request) {
		tok, err := jwt.ParseFromRequest(rq, func(token *jwt.Token) (interface{}, error) {
			return kit.key.Public(), nil
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if !tok.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		usrBytes := tok.Claims["user"].(string)
		var u AuthUser
		if err := json.Unmarshal([]byte(usrBytes), &u); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		vals := make(Values)
		for k, v := range tok.Claims {
			vals[k] = fmt.Sprintf("%v", v)
		}
		ac := &AuthContext{u, vals}
		h(ac, w, rq)
	}
}

// RegisterDefault registers the kit to the default http mux.
func (kit *Authkit) RegisterDefault() {
	kit.Register(http.DefaultServeMux)
}

// Register the kit to the given mux.
func (kit *Authkit) Register(mux *http.ServeMux) {
	mux.Handle(kit.url, kit)
}

// The authkit is a general http handler
func (kit *Authkit) ServeHTTP(w http.ResponseWriter, rq *http.Request) {
	pt := rq.URL.Path
	if pt == kit.url+"js" {
		kit.js(w, rq)
	} else if pt == kit.url+"redirect" {
		kit.redirect(w, rq)
	} else if pt == kit.url+"auth" {
		kit.auth(w, rq)
	} else {
	}
}

func (kit *Authkit) template(ct string, t *template.Template, w http.ResponseWriter, rq *http.Request) {
	w.Header().Set("Content-Type", ct)
	t.Execute(w, struct {
		Providers map[string]AuthRegistration
		Base      string
	}{
		Providers: kit.providers,
		Base:      kit.url,
	})
}

func (kit *Authkit) js(w http.ResponseWriter, rq *http.Request) {
	kit.template("application/javascript", loginTemplate, w, rq)
}

func (kit *Authkit) redirect(w http.ResponseWriter, rq *http.Request) {
	remoteError := rq.FormValue("error")
	if remoteError != "" {
		errDesc := rq.FormValue("error_description")
		http.Error(w, fmt.Sprintf("%s: %s", remoteError, errDesc), http.StatusUnauthorized)
		return
	}
	kit.template("text/html", redirectTemplate, w, rq)
}

func (kit *Authkit) auth(w http.ResponseWriter, rq *http.Request) {
	if err := rq.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	accesscode := rq.FormValue("code")
	state := rq.FormValue("state")
	res := make(map[string]interface{})
	if err := json.Unmarshal([]byte(state), &res); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	network := res["network"].(string)
	redirect := res["redirect_uri"].(string)
	reg, hasNetwork := kit.providers[network]
	if !hasNetwork {
		http.Error(w, fmt.Sprintf("unknown network: %s", network), http.StatusInternalServerError)
		return
	}

	usr, tok, err := oauth(reg, accesscode, redirect)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot authenticate: %s", err), http.StatusUnauthorized)
		return
	}
	t := jwt.New(jwt.GetSigningMethod(signMethod))

	dur, vls, err := kit.TokenExtender(*usr, *tok)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot finalize: %s", err), http.StatusInternalServerError)
		return
	}
	usrBytes, err := json.Marshal(usr)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot marshal user as json: %s", err), http.StatusInternalServerError)
		return
	}
	if vls != nil {
		for k, v := range vls {
			t.Claims[k] = v
		}
	}
	t.Claims["user"] = string(usrBytes)
	t.Claims["exp"] = time.Now().Add(dur).Unix()
	signed, err := t.SignedString(kit.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Authorization", fmt.Sprintf("Bearer %s", signed))
	json.NewEncoder(w).Encode(usr)
}

func oauth(reg AuthRegistration, accesscode, redirectURL string) (*AuthUser, *Token, error) {
	conf := &oauth2.Config{
		ClientID:     reg.ClientID,
		ClientSecret: reg.ClientSecret,
		Scopes:       reg.Scopes,
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  reg.AuthURL,
			TokenURL: reg.AccessTokenURL,
		},
	}

	tok, err := conf.Exchange(oauth2.NoContext, accesscode)
	if err != nil {
		return nil, nil, fmt.Errorf("error when exchanging accesscode to token: %s", err)
	}
	kitToken := &Token{tok.AccessToken, tok.TokenType, tok.RefreshToken, tok.Expiry}
	client := conf.Client(oauth2.NoContext, tok)
	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create request : %s", err)
	}
	var res []interface{}
	for _, uu := range reg.UserinfoURLs {
		req.URL, err = url.Parse(reg.UserinfoBase)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot parse userinfo base '%s': %s", reg.UserinfoBase, err)
		}
		req.URL.Path = ""
		req.URL.Opaque = uu
		rsp, err := client.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot fetch userinfo from '%s': %s", uu, err)
		}
		defer rsp.Body.Close()
		if rsp.StatusCode/100 != 2 {
			dat, _ := ioutil.ReadAll(rsp.Body)
			return nil, nil, fmt.Errorf("cannot fetch userinfo from '%s', Status: %d: %s", uu, rsp.StatusCode, string(dat))
		}
		dat, err := parse(rsp.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot parse response body: %s", err)
		}
		res = append(res, dat)
	}
	userdata := make(map[string]interface{})
	userdata["url"] = res
	log.Printf("userdata: %#v", userdata)
	var authuser AuthUser
	authuser.Network = reg.Network
	authuser.Fields = userdata
	v, err := getValue(reg.PathID, userdata)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get id: %s", err)
	}
	authuser.ID = v
	v, err = getValue(reg.PathEMail, userdata)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get email: %s", err)
	}
	authuser.EMail = v
	v, err = getValue(reg.PathName, userdata)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get name: %s", err)
	}
	authuser.Name = v
	if reg.PathCover != "" {
		v, err = getValue(reg.PathCover, userdata)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot get cover: %s", err)
		}
		authuser.BackgroundURL = v
	}
	if reg.PathPicture != "" {
		v, err = getValue(reg.PathPicture, userdata)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot get picture: %s", err)
		}
		authuser.ThumbnailURL = v
	}
	return &authuser, kitToken, nil
}

func parse(r io.Reader) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	buf, e := ioutil.ReadAll(r)
	if e != nil {
		return nil, e
	}
	if err := json.Unmarshal(buf, &m); err != nil {
		// try an array as response ...
		// this is an ugly hack, but we do not know what the rest endpoint
		// returns :-(
		var ar []interface{}
		if err := json.Unmarshal(buf, &ar); err != nil {
			return nil, err
		}
		m["data"] = ar
	}
	return m, nil
}

func getValue(path string, data map[string]interface{}) (string, error) {
	target := data
	var res string
	parts := strings.Split(path, ".")
	for idx, p := range parts {
		val, err := getSimpleValue(p, target)
		if err != nil {
			return "", err
		}
		if val == nil {
			return "", nil
		}
		if idx < len(parts)-1 {
			target = val.(map[string]interface{})
		} else {
			res = val.(string)
		}
	}
	return res, nil
}

func getSimpleValue(v string, data map[string]interface{}) (interface{}, error) {
	loc := arIndex.FindStringIndex(v)
	if loc != nil {
		index64, err := strconv.ParseInt(v[loc[0]+1:loc[1]-1], 10, 0)
		if err != nil {
			return nil, err
		}
		indx := int(index64)
		key := v[0:loc[0]]
		val, _ := data[key]
		if val == nil {
			return nil, nil
		}
		res := val.([]interface{})
		return res[indx], nil
	}
	return data[v], nil
}
