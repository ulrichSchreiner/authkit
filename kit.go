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
	UserinfoOpaque string   `json:"userinfo_opaque"`
	UserinfoURL    string   `json:"userinfo_url"`
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
type Token map[string]string

// An Authkit stores a map of providers which are identified by a networkname.
type Authkit struct {
	providers          map[string]AuthRegistration
	url                string
	key                *rsa.PrivateKey
	expireTokenSeconds time.Duration
}

// An AuthHandler is a callback function with the current authenticated
// user as the first parameter.
type AuthHandler func(u AuthUser, w http.ResponseWriter, rq *http.Request)

// New returns a new Authkit with the given url as a prefix
func New(url string, expireSeconds int) (*Authkit, error) {
	a := &Authkit{}
	a.providers = make(map[string]AuthRegistration)
	if !strings.HasSuffix(url, "/") {
		url = url + "/"
	}
	a.url = url
	a.expireTokenSeconds = time.Duration(expireSeconds)
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
		h(u, w, rq)
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

	usr, _, err := oauth(reg, accesscode, redirect)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot authenticate: %s", err), http.StatusUnauthorized)
		return
	}
	t := jwt.New(jwt.GetSigningMethod(signMethod))

	usrBytes, err := json.Marshal(usr)
	if err != nil {
		http.Error(w, "cannot marshal user as json", http.StatusInternalServerError)
		return
	}
	t.Claims["user"] = string(usrBytes)
	t.Claims["exp"] = time.Now().Add(time.Second * kit.expireTokenSeconds).Unix()
	signed, err := t.SignedString(kit.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Authorization", fmt.Sprintf("Bearer %s", signed))
	json.NewEncoder(w).Encode(usr)
}

func oauth(reg AuthRegistration, accesscode, redirectURL string) (*AuthUser, Token, error) {
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
	atok := make(Token)
	atok["access_token"] = tok.AccessToken
	atok["token_type"] = tok.TokenType
	atok["refresh_token"] = tok.RefreshToken
	atok["expires_in"] = strconv.Itoa(int(tok.Expiry.Sub(time.Now()).Seconds()))
	client := conf.Client(oauth2.NoContext, tok)
	req, err := http.NewRequest("GET", reg.UserinfoURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse create request : %s", err)
	}
	req.URL, err = url.Parse(reg.UserinfoURL)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse userinfo-url '%s': %s", reg.UserinfoURL, err)
	}
	if reg.UserinfoOpaque != "" {
		req.URL.Path = ""
		req.URL.Opaque = reg.UserinfoOpaque
	}
	rsp, err := client.Do(req)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot fetch userinfo from '%s': %s", reg.UserinfoURL, err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode/100 != 2 {
		dat, _ := ioutil.ReadAll(rsp.Body)
		return nil, nil, fmt.Errorf("cannot fetch userinfo from '%s', Status: %d: %s", reg.UserinfoURL, rsp.StatusCode, string(dat))
	}

	dat, err := parse(rsp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse response body: %s", err)
	}

	var res AuthUser
	res.Network = reg.Network
	res.Fields = dat
	v, err := getValue(reg.PathID, dat)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get id: %s", err)
	}
	res.ID = v
	v, err = getValue(reg.PathEMail, dat)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get email: %s", err)
	}
	res.EMail = v
	v, err = getValue(reg.PathName, dat)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get name: %s", err)
	}
	res.Name = v
	if reg.PathCover != "" {
		v, err = getValue(reg.PathCover, dat)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot get cover: %s", err)
		}
		res.BackgroundURL = v
	}
	if reg.PathPicture != "" {
		v, err = getValue(reg.PathPicture, dat)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot get picture: %s", err)
		}
		res.ThumbnailURL = v
	}
	return &res, atok, nil
}

func parse(r io.Reader) (map[string]interface{}, error) {
	//buf, e := ioutil.ReadAll(r)
	//log.Printf("%s: %#v", e, string(buf))
	m := make(map[string]interface{})

	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return nil, err
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
		if idx < len(parts)-1 {
			target = val.(map[string]interface{})
		} else {
			if val == nil {
				res = ""
			} else {
				res = val.(string)
			}
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
		res := data[key].([]interface{})
		return res[indx], nil
	}
	return data[v], nil
}
