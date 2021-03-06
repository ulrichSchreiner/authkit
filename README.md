# authkit

`authkit` is a small `go` toolkit for an Oauth2 explicit flow and
is great for pure javascript apps which calls stateless REST services 
where the user must be authenticated. You don't have to store a session or
any other credentials store in the backend of your servers. Simply create
a login page, register this application with one of your favourite Oauth2 
providers and let the user login and use your REST services. The services
are full clusterable as long as every instance has the same private key
associated to verify the JWT token.

You can embed this toolkit in your webapp and your browser and server will 
do the oauth2 explicit flow. If the user is successfully authenticated a `JWT` 
token and a user structure is returned to the browser. On the serverside your
code will receive a `AuthUser` which contains the following fields:
```go
// An AuthUser is a Uid and a Name. The backgroundurl
// and the thumbnailurl are optional an can be empty.
type AuthUser struct {
	Network       Provider   `json:"network"`
	ID            string     `json:"id"`
	EMail         string     `json:"email"`
	Name          string     `json:"name"`
	BackgroundURL string     `json:"backgroundurl"`
	ThumbnailURL  string     `json:"thumbnail"`
	Fields        Unparsed   `json:"fields"`
}
```
The `Fields` field contains the structure sent from the provider.

Your client can store the JWT token and embed this value to every call
to one of your REST services. `authkit` also is a small middleware toolkit 
which intercepts the requests and parses the `JWT` token. Your handler 
functions will receive the authenticated user as an additional parameter.

`autkit` 

Put something like this in your server code:

```go
// register your OAUTH-apps with "<scheme>://<server>:<port>/authkit" and
// "<scheme>://<server>:<port>/authkit/redirect"
var kit = authkit.Must("/authkit") // <-- this name will be in the URL
...
kit.Add(authkit.Instance(
  authkit.Google, 
  os.Getenv("GOOGLE_CLIENTID"), 
  os.Getenv("GOOGLE_CLIENTSECRET")))
kit.RegisterDefault()
http.HandleFunc("/authed/", a.Handle(authed))
...
func authed(ac *authkit.AuthContext, w http.ResponseWriter, rq *http.Request) {
	log.Printf("user: %#v", ac.User)
	for k, v := range ac.Claims {
		log.Printf(" - vals[%s] = %s\n", k, v)
	}
}
```
and your client should embed the JS library:
```javascript
<script src="/authkit/js"></script>

authkit.login('google').user(function (usr, tok) {
  ...
});
```

If you want to use some specific webframeworks or don't like the extended
method signature, you can pull the context out of a normal web request:
```go
func normal(w http.ResponseWriter, rq *http.Request) {
	ctx, err := kit.Context(rq)
	if err != nil {
		log.Printf("no valid auth context found: %s", err)
	} else {
		log.Printf("current authenticated user: %#v", ctx.User)
	}
}
```

Current supported providers:

  - Google
  - Github
  - Linkedin
  - Live (Windows)
