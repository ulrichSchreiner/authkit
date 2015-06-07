package authkit

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

import "net/http"

var (
	arIndex = regexp.MustCompile(`\[\d\]`)
)

// AuthRegistration describes a provider to authenticate against.
type AuthRegistration struct {
	Network        string `json:"network"`
	ClientID       string `json:"clientid"`
	ClientSecret   string `json:"clientsecret"`
	Scopes         string `json:"scopes"`
	AuthURL        string `json:"authurl"`
	AccessTokenURL string `json:"accesstokenurl"`
	UserinfoURL    string `json:"userinfo_url"`
	PathEMail      string `json:"pathemail"`
	PathID         string `json:"pathid"`
	PathName       string `json:"pathname"`
	PathPicture    string `json:"pathpicture"`
	PathCover      string `json:"pathcover"`
}

// An Unparsed value is a raw map with the unparsed json contents.
type Unparsed map[string]interface{}

// An AuthUser is a Uid and a Name. The backgroundurl
// and the thumbnailurl are optional an can be empty.
type AuthUser struct {
	Network       string   `json:"network"`
	UID           string   `json:"uid"`
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
	providers map[string]AuthRegistration
}

// New returns a new Authkit with the given providers. If a provider is non
// in then list of known defaults, it will be an empty registration.
func New(providers ...string) *Authkit {
	a := &Authkit{}
	a.providers = make(map[string]AuthRegistration)
	for _, p := range providers {
		r := GetRegistry(p)
		a.providers[p] = r
	}
	return a
}

// Add will add the given registration to the map of providers. If there
// is already a provider with the same 'Network' name, the old one will
// be overwritten.
func (kit *Authkit) Add(r AuthRegistration) {
	kit.providers[r.Network] = r
}

func (kit *Authkit) ServeHTTP(w http.ResponseWriter, rq *http.Request) {
	if err := rq.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	accesscode := rq.FormValue("accesscode")
	network := rq.FormValue("network")
	redirect := rq.FormValue("redirect")
	reg, hasNetwork := kit.providers[network]
	if !hasNetwork {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("unknown network: %s", network)))
		return
	}

	usr, tok, err := auth(reg, accesscode, redirect)
	fmt.Printf("%v, %v, %s\n", usr, tok, err)
}

func auth(reg AuthRegistration, accesscode, redirectURL string) (*AuthUser, Token, error) {
	conf := &oauth2.Config{
		ClientID:     reg.ClientID,
		ClientSecret: reg.ClientSecret,
		Scopes:       strings.Split(reg.Scopes, ","),
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  reg.AuthURL,
			TokenURL: reg.AccessTokenURL,
		},
	}
	tok, err := conf.Exchange(oauth2.NoContext, accesscode)
	if err != nil {
		return nil, nil, err
	}
	atok := make(Token)
	atok["access_token"] = tok.AccessToken
	atok["token_type"] = tok.TokenType
	atok["refresh_token"] = tok.RefreshToken
	atok["expires_in"] = strconv.Itoa(int(tok.Expiry.Sub(time.Now()).Seconds()))
	client := conf.Client(oauth2.NoContext, tok)
	rsp, err := client.Get(reg.UserinfoURL)
	if err != nil {
		return nil, nil, err
	}
	defer rsp.Body.Close()

	dat, err := parse(rsp.Body)
	if err != nil {
		return nil, nil, err
	}

	var res AuthUser
	res.Network = reg.Network
	res.Fields = dat
	v, err := getValue(reg.PathID, dat)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get id: %s", err)
	}
	res.UID = v
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
		res := data[key].([]interface{})
		return res[indx], nil
	}
	return data[v], nil
}
