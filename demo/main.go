package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ulrichSchreiner/authkit"
)

var indexTemplate = template.Must(template.New("index").Parse(`
<html>
<head>
  <title>Test Application</title>
  <script src="http://code.jquery.com/jquery-2.1.4.min.js"></script>
  <script src="/authkit/js"></script>
</head>
<body>
<script>
var user;
var token;
function login () {
  authkit.login($("#providerList").val()).user(function (usr, tok) {
    user = usr;
    token = tok;
    $("#token").text(tok);
    $("#user").text(JSON.stringify(usr,null,4));
    $("#execRQ").prop("disabled",false);
  });
}

function execRequest (path) {
  var req = new XMLHttpRequest();
  req.open("GET", path);
  req.setRequestHeader("Authorization", token);
  req.send(null);
}

$(function () {
  Object.keys(authkit.providers()).forEach(function(p) {
    $("#providerList").append("<option value='"+p+"'>"+p+"</option>")
  });
});
</script>

<select id="providerList"></select>

<button onclick="login()">Login </button>
<button onclick="execRequest('/authed/')" id="execRQ" disabled=disabled>Execute Secure Request</button>
<button onclick="execRequest('/normal/')" id="execNormal" >Execute unsecure Request</button>
<hr size="1" width="90%">
<div><tt id="token"></tt></div>
<div><tt><pre id="user"></pre></tt></div>
</body>
</html>

`))

var kit = authkit.Must("/authkit")

func index(w http.ResponseWriter, rq *http.Request) {
	indexTemplate.Execute(w, nil)
}

func authed(ac *authkit.AuthContext, w http.ResponseWriter, rq *http.Request) {
	log.Printf("user: %#v", ac.User)
	for k, v := range ac.Claims {
		log.Printf(" - vals[%s] = %s\n", k, v)
	}
}

func normal(w http.ResponseWriter, rq *http.Request) {
	ctx, err := kit.Context(rq)
	if err != nil {
		log.Printf("no valid auth context found: %s", err)
	} else {
		log.Printf("current authenticated user: %#v", ctx.User)
	}
}

func extend(u authkit.AuthUser, t authkit.Token) (time.Duration, authkit.Values, error) {
	v := make(authkit.Values)
	v["name"] = u.Name + " - " + u.EMail
	return 60 * time.Second, v, nil
}

func main() {
	key, e := os.Open(os.Getenv("AUTHKIT_KEY"))
	if e == nil {
		kit.UseKey(key)
	} else {
		fmt.Printf("no key found, generated one:\n%s\n", kit.DumpKey())
	}
	kit.TokenExtender = kit.TokenExtender.Merge(extend)
	kit.Add(authkit.Provider(authkit.Google, os.Getenv("GOOGLE_CLIENTID"), os.Getenv("GOOGLE_CLIENTSECRET")))
	kit.Add(authkit.Provider(authkit.Github, os.Getenv("GITHUB_CLIENTID"), os.Getenv("GITHUB_CLIENTSECRET")))
	kit.Add(authkit.Provider(authkit.Live, os.Getenv("LIVE_CLIENTID"), os.Getenv("LIVE_CLIENTSECRET")))
	kit.Add(authkit.Provider(authkit.LinkedIn, os.Getenv("LINKEDIN_CLIENTID"), os.Getenv("LINKEDIN_CLIENTSECRET")))
	kit.RegisterDefault()

	log.Printf("%#v", kit)
	http.HandleFunc("/authed/", kit.Handle(authed))
	http.HandleFunc("/normal/", normal)
	http.HandleFunc("/", index)
	http.ListenAndServe(":8080", nil)
}
