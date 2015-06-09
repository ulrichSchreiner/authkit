# authkit

`authkit` is a small `go` toolkit for an Oauth2 explicit flow. You can embed
this toolkit in your webapp and your browser and server will do the oauth2 
explicit flow. If the user is successfully authenticated a `JWT` token
and a user structure is returned to the browser.

Your client can then store the JWT token and embed this value to every call
to one of your REST services. `authkit` also is a small middleware toolkit 
which intercepts the requests and parses the `JWT` token. Your handler 
functions will receive the authenticated user as an additional parameter.

Put something like this in your server code:

```
// register your OAUTH-apps with "<scheme>://<server>:<port>/authkit" and
// "<scheme>://<server>:<port>/authkit/redirect"
a, e := authkit.New("/authkit") // <-- this name will be in the URL
...
a.Add(authkit.Provider(
  authkit.GoogleNetwork, 
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
```
<script src="/authkit/js"></script>

authkit.login('google').user(function (usr, tok) {
  ...
});
```

Current supported providers:

  - Google
  - Github
  - Linkedin
  - Windows (Live)
