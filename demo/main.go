package main

import (
	"html/template"
	"log"
	"net/http"
	"os"

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

function execRequest () {
  var req = new XMLHttpRequest();
  req.open("GET", "/authed/");
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
<button onclick="execRequest()" id="execRQ" disabled=disabled>Execute Request</button>
<hr size="1" width="90%">
<div><tt id="token"></tt></div>
<div><tt><pre id="user"></pre></tt></div>
</body>
</html>

`))

func index(w http.ResponseWriter, rq *http.Request) {
	indexTemplate.Execute(w, nil)
}

func test(u authkit.AuthUser, w http.ResponseWriter, rq *http.Request) {
	log.Printf("user: %#v", u)
}

func main() {
	a, e := authkit.New("/authkit", 60)
	if e != nil {
		panic(e)
	}
	key, e := os.Open(os.Getenv("AUTHKIT_KEY"))
	if e != nil {
		panic(e)
	}
	a.UseKey(key)
	a.Add(authkit.Provider(authkit.GoogleNetwork, os.Getenv("GOOGLE_CLIENTID"), os.Getenv("GOOGLE_CLIENTSECRET")))
	a.Add(authkit.Provider(authkit.GithubNetwork, os.Getenv("GITHUB_CLIENTID"), os.Getenv("GITHUB_CLIENTSECRET")))
	a.Add(authkit.Provider(authkit.LiveNetwork, os.Getenv("LIVE_CLIENTID"), os.Getenv("LIVE_CLIENTSECRET")))
	a.Add(authkit.Provider(authkit.LinkedInNetwork, os.Getenv("LINKEDIN_CLIENTID"), os.Getenv("LINKEDIN_CLIENTSECRET")))
	a.RegisterDefault()

	log.Printf("%#v", a)
	http.HandleFunc("/authed/", a.Handle(test))
	http.HandleFunc("/", index)
	http.ListenAndServe(":8080", nil)
}
