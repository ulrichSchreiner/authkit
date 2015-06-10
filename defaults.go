package authkit

const (
	// Google constant.
	Google Provider = "google"
	// Github constant.
	Github Provider = "github"
	// Live constant
	Live Provider = "windows"
	// LinkedIn constant
	LinkedIn Provider = "linkedin"
)

// A ProviderRegistry contains all registerd providers.
type ProviderRegistry map[Provider]AuthRegistration

var (
	defaultBackends = ProviderRegistry{
		Google: AuthRegistration{
			Network:        Google,
			Scopes:         []string{"openid", "profile", "email", "https://www.googleapis.com/auth/plus.me"},
			AuthURL:        "https://accounts.google.com/o/oauth2/auth",
			AccessTokenURL: "https://accounts.google.com/o/oauth2/token",
			UserinfoBase:   "https://www.googleapis.com",
			UserinfoURLs:   []string{"/plus/v1/people/me"},
			PathID:         "url[0].id",
			PathEMail:      "url[0].emails[0].value",
			PathName:       "url[0].displayName",
			PathPicture:    "url[0].image.url",
			PathCover:      "url[0].cover.coverPhoto.url",
		},
		Github: AuthRegistration{
			Network:        Github,
			Scopes:         []string{"user:email"},
			AuthURL:        "https://github.com/login/oauth/authorize",
			AccessTokenURL: "https://github.com/login/oauth/access_token",
			UserinfoBase:   "https://api.github.com",
			UserinfoURLs:   []string{"/user", "/user/emails"},
			PathID:         "url[0].login",
			PathEMail:      "url[1].data[0].email",
			PathName:       "url[0].name",
			PathPicture:    "url[0].avatar_url",
			PathCover:      "",
		},
		Live: AuthRegistration{
			Network:        Live,
			Scopes:         []string{"wl.signin"},
			AuthURL:        "https://login.live.com/oauth20_authorize.srf",
			AccessTokenURL: "https://login.live.com/oauth20_token.srf",
			UserinfoBase:   "https://apis.live.net",
			UserinfoURLs:   []string{"/v5.0/me"},
			PathID:         "url[0].id",
			PathEMail:      "url[0].emails.account",
			PathName:       "url[0].name",
			PathPicture:    "",
			PathCover:      "",
		},
		LinkedIn: AuthRegistration{
			Network:        LinkedIn,
			Scopes:         []string{"r_basicprofile", "r_emailaddress"},
			AuthURL:        "https://www.linkedin.com/uas/oauth2/authorization",
			AccessTokenURL: "https://www.linkedin.com/uas/oauth2/accessToken",
			UserinfoURLs:   []string{"/v1/people/~:(picture-url,first-name,last-name,id,formatted-name,email-address)?format=json"},
			UserinfoBase:   "https://api.linkedin.com",
			PathID:         "url[0].id",
			PathEMail:      "url[0].emailAddress",
			PathName:       "url[0].formattedName",
			PathPicture:    "url[0].pictureUrl",
			PathCover:      "",
		},
	}
)

// GetRegistry returns a registry description for the given backend or an
// empty registration block.
func GetRegistry(backend Provider) AuthRegistration {
	res, _ := defaultBackends[backend]
	return res
}

// Instance returns a new registration provider with the given clientid
// and clientsecret.
func Instance(backend Provider, clientid, clientsecret string, scopes ...string) AuthRegistration {
	b := GetRegistry(backend)
	b.ClientID = clientid
	b.ClientSecret = clientsecret
	if scopes != nil && len(scopes) > 0 {
		b.Scopes = scopes
	}
	return b
}

// FillDefaults fills the given registration struct with the default values
// from the backend. The values are only overwritten if they are empty.
func FillDefaults(backend Provider, reg AuthRegistration) AuthRegistration {
	def := GetRegistry(backend)
	if reg.Scopes == nil || len(reg.Scopes) == 0 {
		reg.Scopes = def.Scopes
	}
	if reg.AuthURL == "" {
		reg.AuthURL = def.AuthURL
	}
	if reg.AccessTokenURL == "" {
		reg.AccessTokenURL = def.AccessTokenURL
	}
	if len(reg.UserinfoURLs) == 0 {
		reg.UserinfoURLs = def.UserinfoURLs
	}
	if reg.PathID == "" {
		reg.PathID = def.PathID
	}
	if reg.PathEMail == "" {
		reg.PathEMail = def.PathEMail
	}
	if reg.PathName == "" {
		reg.PathName = def.PathName
	}
	if reg.PathPicture == "" {
		reg.PathPicture = def.PathPicture
	}
	if reg.PathCover == "" {
		reg.PathCover = def.PathCover
	}
	return reg
}
