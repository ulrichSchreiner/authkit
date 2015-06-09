package authkit

const (
	// Google constant.
	Google = "google"
	// Github constant.
	Github = "github"
	// Live constant
	Live = "windows"
	// LinkedIn constant
	LinkedIn = "linkedin"
)

var (
	defaultBackends = map[string]AuthRegistration{
		Google: AuthRegistration{
			Network:        Google,
			Scopes:         []string{"openid", "profile", "email", "https://www.googleapis.com/auth/plus.me"},
			AuthURL:        "https://accounts.google.com/o/oauth2/auth",
			AccessTokenURL: "https://accounts.google.com/o/oauth2/token",
			UserinfoURL:    "https://www.googleapis.com/plus/v1/people/me",
			PathID:         "id",
			PathEMail:      "emails[0].value",
			PathName:       "displayName",
			PathPicture:    "image.url",
			PathCover:      "cover.coverPhoto.url",
		},
		Github: AuthRegistration{
			Network:        Github,
			Scopes:         []string{"user:email"},
			AuthURL:        "https://github.com/login/oauth/authorize",
			AccessTokenURL: "https://github.com/login/oauth/access_token",
			UserinfoURL:    "https://api.github.com/user",
			PathID:         "login",
			PathEMail:      "email",
			PathName:       "name",
			PathPicture:    "avatar_url",
			PathCover:      "",
		},
		Live: AuthRegistration{
			Network:        Live,
			Scopes:         []string{"wl.signin"},
			AuthURL:        "https://login.live.com/oauth20_authorize.srf",
			AccessTokenURL: "https://login.live.com/oauth20_token.srf",
			UserinfoURL:    "https://apis.live.net/v5.0/me",
			PathID:         "id",
			PathEMail:      "emails.account",
			PathName:       "name",
			PathPicture:    "",
			PathCover:      "",
		},
		LinkedIn: AuthRegistration{
			Network:        LinkedIn,
			Scopes:         []string{"r_basicprofile", "r_emailaddress"},
			AuthURL:        "https://www.linkedin.com/uas/oauth2/authorization",
			AccessTokenURL: "https://www.linkedin.com/uas/oauth2/accessToken",
			UserinfoOpaque: "/v1/people/~:(picture-url,first-name,last-name,id,formatted-name,email-address)?format=json",
			UserinfoURL:    "https://api.linkedin.com",
			PathID:         "id",
			PathEMail:      "emailAddress",
			PathName:       "formattedName",
			PathPicture:    "pictureUrl",
			PathCover:      "",
		},
	}
)

// GetRegistry returns a registry description for the given backend or an
// empty registration block.
func GetRegistry(backend string) AuthRegistration {
	res, _ := defaultBackends[backend]
	return res
}

// Provider returns a new registration provider with the given clientid
// and clientsecret.
func Provider(backend, clientid, clientsecret string, scopes ...string) AuthRegistration {
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
func FillDefaults(backend string, reg AuthRegistration) AuthRegistration {
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
	if reg.UserinfoURL == "" {
		reg.UserinfoURL = def.UserinfoURL
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
