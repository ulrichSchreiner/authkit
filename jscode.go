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
var __authkit__state__ = {
  authCallback : "__authkit__"+parseInt(Math.random()*1e12,10).toString(36),
  providers : {}
};

{{ $base := .Base }}
{{ range $key, $value := .Providers }}
__authkit__state__.providers["{{ $value.Network }}"] = {
  network : "{{ $value.Network }}",
  authurl : "{{ $value.AuthURL }}",
  client_id : "{{ $value.ClientID }}",
  scopes : "{{ join $value.Scopes " " }}",
  redirect: "{{ $base }}redirect"
};
{{ end }}

var authkit = {
  providers : function () {
    return __authkit__state__.providers;
  },
  provider : function (p) {
    return __authkit__state__.providers[p];
  },
  login : function (provider) {
    var p = authkit.provider(provider);
    if (!p) return;
    var scopes = encodeURIComponent(p.scopes);
    var redir = encodeURIComponent(window.location.origin+p.redirect);
    var state = encodeURIComponent(JSON.stringify({network:p.network,redirect_uri:redir,cbid:__authkit__state__.authCallback}));
    var authU = p.authurl+"?redirect_uri="+redir+"&response_type=code&client_id="+p.client_id+"&state="+state;
    if (p.scopes) {
      authU = authU + "&scope="+scopes;
    }
    var self = this;
    self.user = function (cb) { this.authCB = cb; };
    window[__authkit__state__.authCallback] = function (token, usr) {
      console.log(usr);
      self.authCB(usr, token)
    }
    popup(authU, 500, 600);
    return self;
  }
};

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
           var tok = req.getResponseHeader("Authorization");
           var usr = JSON.parse(req.responseText);
           window.opener[cbid](tok, usr);
           window.close();
        }
        else if(req.status == 400) {
            console.log('There was an error processing the access code:',req.responseText)
        }
        else {
          console.log('something other than 200 was returned:',req.responseText)
        }
      }
    };
    req.send(null);
	</script>
</body>
</html>
`
