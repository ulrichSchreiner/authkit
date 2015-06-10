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
token and a user structure is returned to the browser.

Your client can store the JWT token and embed this value to every call
to one of your REST services. `authkit` also is a small middleware toolkit 
which intercepts the requests and parses the `JWT` token. Your handler 
functions will receive the authenticated user as an additional parameter.

`autkit` 

Put something like this in your server code:

```go
// register your OAUTH-apps with "<scheme>://<server>:<port>/authkit" and
// "<scheme>://<server>:<port>/authkit/redirect"
a, e := authkit.New("/authkit") // <-- this name will be in the URL
...
a.Add(authkit.Provider(
  authkit.Google, 
  os.Getenv("GOOGLE_CLIENTID"), 
  os.Getenv("GOOGLE_CLIENTSECRET")))
a.RegisterDefault()
http.HandleFunc("/authed/", a.Handle(test))
...
func test(ac *authkit.AuthContext, w http.ResponseWriter, rq *http.Request) {
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

Current supported providers:

  - Google
  - Github
  - Linkedin
  - Live (Windows)
