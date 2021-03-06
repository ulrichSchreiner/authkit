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
  accesstype: "{{ $value.AccessType }}",
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
  login : function (provider,base) {
    var p = authkit.provider(provider);
    if (!p) return;
    if (!base) base = window.location.origin;
    var scopes = encodeURIComponent(p.scopes);
    var redir = encodeURIComponent(base+p.redirect);
    var state = encodeURIComponent(JSON.stringify({network:p.network,redirect_uri:redir,cbid:__authkit__state__.authCallback}));
    var authU = p.authurl+"?redirect_uri="+redir+"&response_type=code&client_id="+p.client_id+"&state="+state;
    if (p.scopes) {
      authU = authU + "&scope="+scopes;
    }
    if (p.accesstype) {
      authU = authU + "&access_type="+p.accesstype;
    }
    var self = this;
    self.user = function (cb) { this.authCB = cb; };
		self.cbid = __authkit__state__.authCallback;
    popup(authU, 500, 600, this);
    return self;
  }
};

function popup (u, w, h, target) {
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
	win = window.open(u, "_blank", feat);
	// use polling because of an ugly IOS/chrome bug where window.opener is null
	poll = setInterval(function() {
      if (win && win.closed) {
          clearInterval(poll);
          returnOauth(target);
      }
  } , 300);
}

function returnOauth (target) {
	var cbid = target.cbid;
	var token = localStorage.getItem(cbid+"-token");
	var usr = JSON.parse(localStorage.getItem(cbid+"-user"));
	var err = localStorage.getItem(cbid+"-error");

	localStorage.removeItem(cbid+"-token");
	localStorage.removeItem(cbid+"-user");
	localStorage.removeItem(cbid+"-error");

	if (token && usr) {
		if (target.authCB) {
			target.authCB(usr, token);
		}
	} else if (err) {
		if (target.authCB) {
			target.authCB(null, null, err);
		}
	}
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
		console.log("code: ", params.code, "state: ", params.state);

    req.onreadystatechange = function (e) {
      if (req.readyState == 4) {
        if(req.status == 200){
           var tok = req.getResponseHeader("Authorization");
           var usr = req.responseText;
					 localStorage.setItem(cbid+"-token", tok);
					 localStorage.setItem(cbid+"-user", usr);
           window.close();
        }
        else if(req.status == 400) {
            console.log('There was an error processing the access code:',req.responseText)
						localStorage.setItem(cbid+"-error", req.responseText);
            window.close();
        }
        else {
          console.log('something other than 200 was returned:',req.responseText)
					localStorage.setItem(cbid+"-error", req.responseText);
          window.close();
        }
      }
    };
    req.send(null);
	</script>
</body>
</html>
`
