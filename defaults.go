package authkit

const (
	// GoogleNetwork is a constant for google
	GoogleNetwork = "google"
	// GithubNetwork is a constant for github
	GithubNetwork = "github"
)

var (
	defaultBackends = map[string]AuthRegistration{
		GoogleNetwork: AuthRegistration{
			Scopes:         "openid,profile,email,https://www.googleapis.com/auth/plus.me",
			AuthURL:        "https://accounts.google.com/o/oauth2/auth",
			AccessTokenURL: "https://accounts.google.com/o/oauth2/token",
			UserinfoURL:    "https://www.googleapis.com/plus/v1/people/me",
			PathID:         "emails[0].value",
			PathEMail:      "emails[0].value",
			PathName:       "displayName",
			PathPicture:    "image.url",
			PathCover:      "cover.coverPhoto.url",
		},
		GithubNetwork: AuthRegistration{
			Scopes:         "user:email",
			AuthURL:        "https://github.com/login/oauth/authorize",
			AccessTokenURL: "https://github.com/login/oauth/access_token",
			UserinfoURL:    "https://api.github.com/user",
			PathID:         "login",
			PathEMail:      "email",
			PathName:       "name",
			PathPicture:    "avatar_url",
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
func Provider(backend, clientid, clientsecret, scopes string) AuthRegistration {
	b := GetRegistry(backend)
	b.ClientID = clientid
	b.ClientSecret = clientsecret
	b.Scopes = scopes
	return b
}

// FillDefaults fills the given registration struct with the default values
// from the backend. The values are only overwritten if they are empty.
func FillDefaults(backend string, reg AuthRegistration) AuthRegistration {
	def := GetRegistry(backend)
	if reg.Scopes == "" {
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