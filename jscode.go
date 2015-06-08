package authkit

import (
	"html/template"
	"strings"
)

var funcMap = template.FuncMap{
	"join": strings.Join,
}

var loginTemplate = template.Must(template.New("login").Funcs(funcMap).Parse(loginJS))
var loginJS = `
var data = {
{{ $base := .Base }}
{{ range $key, $value := .Providers }}
  {{ $value.Network }} : {
    network : "{{ $value.Network }}",
    authurl : "{{ $value.AuthURL }}",
    client_id : "{{ $value.ClientID }}",
    scopes : "{{ join $value.Scopes " " }}",
    redirect: "{{ $base }}redirect"
  },
{{ end }}
  authkit_version : "{{ .Version }}",
  authCallback : "__authkit__"+parseInt(Math.random()*1e12,10).toString(36)
};

function login(provider) {
  var p = data[provider];
  if (!p) return;
  var scopes = encodeURIComponent(p.scopes);
  var redir = encodeURIComponent(window.location.origin+p.redirect);
  var state = encodeURIComponent(JSON.stringify({network:p.network,redirect_uri:redir,cbid:data.authCallback}));
  var authU = p.authurl+"?redirect_uri="+redir+"&response_type=code&client_id="+p.client_id+"&state="+state;
  if (p.scopes) {
    authU = authU + "&scope="+scopes;
  }
  this.popup(authU, 500, 600);
}

function popup (u, w, h) {
  var documentElement = document.documentElement;

	// Multi Screen Popup Positioning (http://stackoverflow.com/a/16861050)
	//   Credit: http://www.xtf.dk/2011/08/center-new-popup-window-even-on.html
	// Fixes dual-screen position                         Most browsers      Firefox
	var dualScreenLeft = window.screenLeft !== undefined ? window.screenLeft : screen.left;
	var dualScreenTop = window.screenTop !== undefined ? window.screenTop : screen.top;

	var width = window.innerWidth || documentElement.clientWidth || screen.width;
	var height = window.innerHeight || documentElement.clientHeight || screen.height;

	var left = ((width - w) / 2) + dualScreenLeft;
	var top  = ((height - h) / 2) + dualScreenTop;
	var feat = "resizeable=true,height=" + h + ",width=" + w + ",left=" + left + ",top="  + top
	window.open(u, "_blank", feat);
}
      
function init () {
  if (!window[data.authCallback]) {
    window[data.authCallback] = function (token) {
      alert(token);
      //self.orcaToken = token;
      //self.$.authuser.go();
    }
  }
}
init ();
`
var redirectTemplate = template.Must(template.New("redirect").Funcs(funcMap).Parse(redirect))
var redirect = `
<html>
<body>
  <script>
	  // First, parse the query string
    var params = {}, queryString = location.search.substring(1),
        regex = /([^&=]+)=([^&]*)/g, m;
    while (m = regex.exec(queryString)) {
      params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
    }
    
    var req = new XMLHttpRequest();
    var cbid = JSON.parse(params.state).cbid;
    req.open('GET', '{{ .Base }}auth?code='+params.code+"&state="+params.state, true);
    
    req.onreadystatechange = function (e) {
      if (req.readyState == 4) {
        if(req.status == 200){
           var tok = req.getResponseHeader("orca-token");
           window.opener[cbid](tok);
           //window.close();
        }
        else if(req.status == 400) {
            alert('There was an error processing the access code.')
        }
        else {
          alert('something else other than 200 was returned')
        }
      }
    };
    req.send(null);
	</script>
</body>
</html>
`
