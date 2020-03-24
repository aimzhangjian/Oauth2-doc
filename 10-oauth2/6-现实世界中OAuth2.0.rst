现实世界中的OAuth2.0
======================================

授权许可类型
--------------------------------------

OAuth2.0核心协议定位为一个框架而不是单个协议。通过保持协议的核心概念稳固和支持在特定领域进行扩展，OAuth2.0支持以多种不同方式应用。OAuth2.0最关键的一个变化就是授权许可，OAuth2.0提供多种授权许可类型

隐式许可类型

隐式许可类型直接从授权端点返回令牌，因此隐式许可类型只能使用前端信道和授权服务器通信，隐式许可流程不可用于获取刷新令牌。在授权服务器授权端点增加如下处理::

    var getScopesFromForm = function(body){
        return __.filter(__.keys(body),function(s){
            return __.string.startWith(s, 'scope_');
        }).map(function(s){return s.slice{'scope_'.length});
    };


    } else if (query.response_type == 'token'){
        var rscope = getScopeFromForm(req.body);//获取请求体中请求权限范围
        var client = getClient(query.client_id);
        var cscope = client.scope ? client.scope.split(' ') : undefined;
        if(__.difference(rscope, cscope).length > 0){
            var urlParsed = buildUrl(query.redirect_uri, {}, qs.stringify({error: 'invalid_scope'}));
            res.redirect(urlParsed);
            return;
        }
        var access_token = randomstring.generate();
        nosql.insert({access_token: access_token, client_id: clientID, scope: rscope});
        var token_response = {access_token: access_token, token_type: 'Bearer', scope: rescope.join('')};
        if(query.state){
            token_response.state =query.state;
        }

        var urlParsed = buildUrl(query.redirect_uri, {}, qs.stringify(token_response));
        res.redirect(urlParsed);
        return;
    }

客户端凭证许可类型

在客户端凭证许可类型中资源拥有者被塞进客户端，没有用户代理存在，许可流程只使用后端信道，客户端代表自己从令牌端点获取令牌，grant_type参数值为client_credentials，没有授权码或者其他用于换取令牌的临时凭证

修改授权服务器令牌端点，添加处理客户端凭证许可类型::

    } else if (req.body.grant_type == 'client_credentials'){
        var rscope = req.body.scope ? req.body.scope.split(' ') : undefined;
        var cscope = client.scope ? client.scope.split('') : undefined;
        if(__.difference(rscope, cscope).length > 0){
            res.status(400).json({error: 'invalid_scope'});
            return;
        }
        var access_token = randomstring.generate();
        var token_response = {access_token: access_token, token_type: 'Bearer', scope: rscope.join(' ')};
        nosql.insert({access_token: access_token, client_id: clientId, scope: rscope});
        res.status(200).json(token_response);
        return;
    }

客户端请求令牌::

    var form_data = qs.stringify({
        grant_type: 'client_credentials',
        scope: client.scope
    });
    var headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic' + encodeClientCredentials(client.client_id, client.client_secret)
    };
    var tokRes = request('POST', authServer.tokenEndpoint, {
        body: form_data,
        headers: headers
    });
    if(tokRes.statusCode >= 200 && tokRes.statusCode < 300){
        var body = JSON.parse(tokRes.getBody());
        access_token = body.access_token;
        scope = body.scope;
        res.render('index', {access_token: access_token, scope: scope});
    } else {
        res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
    }

资源拥有者凭证许可类型

资源拥有者凭证许可类型，又叫密码流程，客户端通过向用户索取用户凭证，然后用这个凭证换取令牌

修改授权服务器令牌端点代码，增加密码流程处理代码::

    var getUser = function(username){
        return userInfo[username]
    }

    var username = req.body.username;
    var user = getUser(username);
    if(!user){
        res.status(401).json({error: 'invalid_grant'});
        return;
    }
    var password = req.body.password;
    if(user.password != password){
        res.status(401).json({error: 'invalid_grant'});
        return;
    }
    var rscope = req.body.scope ? req.body.scope.split('') : undefined;
    var cscope = client.scope ? client.scope.split(' ') : undefined;
    if(__.difference(rscope, cscope).length > 0){
        res.status(401).json({error: 'invalid_scope'});
        return;
    }
    var access_token = randomstring.generate();
    var refresh_token = randomstring.generate();
    nosql.insert({access_token: access_token, client_id: clientId, scope: rscope});
    nosql.insert({refresh_token: refresh_token, client_id: clientId, scope: rscope});
    var token_response = {access_token: access_token, token_type: 'Bearer', refresh_token: refresh_token, socpe: rscope.join(' ')};
    res.status(200).json(token_response);

断言许可类型

断言许可类型是有OAuth工作组发布的第一个官方扩展许可类型，在这种许可类型下，客户端会得到一条结构化且被加密的信息，叫作断言，使用断言向授权服务器获取令牌。目前有两种标准化的断言格式：一种使用安全断言标记语言（SAML）；另一种使用JSON Web Token（JWT）。这种许可类型只使用后端信道，与客户端凭证许可类型很相似，没有明确的资源拥有者参与，由此颁发的令牌所关联的权限取决于所出示的断言。

选择合适的许可类型

客户端是否代表特定的资源拥有者:

 - 是否可以通过用户的Web浏览器将其引导至一个网页，如果可以，就使用基于重定向的许可流程：授权码或者隐式许可流程

客户端是否完全运行在浏览器内:

 - 如果是则使用隐式许可类型。如果不是，则要么运行在Web服务器上，要么原生运行在用户计算机，这种情况下应该使用授权码许可类型

客户端是原生应用吗:

 - 如果是还因该在授权码许可类型的基础上使用特定的安全扩展，比如动态注册或者代码证明密钥（PKCE）

客户端代表自身吗:

 - 这种情况包括不针对单个用户的API访问。如果是这样则因该使用客户端凭证许可流程。如果需要通过参数指定作用于哪个用户，则考虑使用基于重定向的许可流程

客户端是否在权威性第三方的指示下运行:
 - 这个第三方是否能直接提供一些证明，让你能够代表它执行任务？如果是这样，则因该使用断言许可流程。使用哪种断言取决于授权服务器和颁发断言的第三方

客户端是否无法在浏览器中对用户重定向:
 - 用户是否具有能够提供给你简单用户凭证？是否没有其他选择？如果是这样，那么可以使用资源拥有者凭证许可类型。

客户端部署:
- 客户端可以初略的分为3类：Web应用、浏览器应用、原生应用

Web应用

Web应用能充分的利用前端信道和后端信道整两种通信方式。Web应用很容易有效地使用授权码、客户端凭证或断言许可类型

浏览器应用

浏览器应用完全运行在浏览器内一般使用JavaScript，虽然应用的代码确实需要由Web服务器提供，但代码本身并不在服务器上运行，Web服务器也不会维护应用任何运行时状态。最适合这类应用的是隐式许可流程::

    var client = {
        'client_id': 'oauth-client-1',
        'redirect_uris': ['http://localhost:9000/callback'],
        'scope': 'foo bar'
    }

    var authServer = {
        authorizationEndpoint: 'http://localhost:9001/authorize'
    }

    var protectedResource = 'http://localhost:9002/resource';
    
    var state = generateState(32);
    localStorage.setItem('oauth-state', state);
    location.href = authServer.authorizationEndpoint + '?' + 
        'response_type=token' + 
        '&state=' + state +
        '&scope=' + encodeURIComponent(client.scope) + 
        '&client_id=' + encodeURIComponent(client.client_id) + 
        '&redirect_rui=' + encodeURIComponent(client.redirect_uris[0]);
    
    var h = location.hash.substring(1);
    var whitelist = ['access_token', 'state']
    callbackData = {};
    h.split('&').forEach(function (e){
        var d = e.split('=');

        if(whitelist.indexOf(d[0] > -1)){
            callbackData[d[0]] = d[1];
        }
    });

    if(callbackData.state !== localStorage.getItem('oauth-state')){
        callbackData = null;
        $('.oauth-protected-resource').text("Error state value did not match");
    } else {
        $('.oauth-access-token').text(callbackData.access_token);
    }

原生应用

原生应用是直接在最终用户的设备上运行的应用。这类应用很容易使用后端信道，直接向远服务器发送HTTP请求即可。为了使用前端信道发送请求，原生应用需要能够访问操作系统上的浏览器或者在应用中嵌入一个浏览器视窗，将用户直接引导至授权服务器。可以采用如下方式:

 - 内嵌在应用内、运行在localhost上的Web服务器

 - 具有通知推送能力的远程Web服务器，能向应用推送通知

 - 自定义的URI格式，在操作系统上注册之后，一旦收到该URI格式请求，应用就会被唤起

在移动设备上，自定义URI格式是最常用的。授权码许可、客户端凭证许可、和断言许可流程都适用于原生客户端，但不推荐使用隐式许可流程，因为应用能在浏览器之外保留信息::

    var client = {
        "client_id": "native-client-1",
        "client_secret": "oauth-native-secret-1",
        "redirect_uris": ["com.oauhtinaction.mynativeapp:/"],//自定义URI格式，只要系统浏览器发现以com.oauhtinaction.mynativeapp:/开头但URL，该应用就会被调用，并且使用一个特殊的处理函数来处理
        "scope": "foo bar"
    };
    var authServer = {
        authorizationEndpoint: 'http://localhost:9001/authorize',
        tokenEndpoint: 'http://localhost:9001/token',
    }
    var protectedResource = 'http://lcoalhost:9002/resource';
    var state = generateState(32);
    localStorage.setItem('oauth-state', state);
    var url = authServer.authorizationEndpoint + '?' + 
        'response_type=code' + 
        '&state=' + state + 
        '&scope=' + encodeURIComponent(client.scope) + 
        '&client_id=' + encodeURIComponent(client.cliet_id) + 
        '&redirect_uri=' + encodeURIComponent(client.redirect_uris[0]);
    cordova.InAppBrowser.open(url, '_system');//调用系统浏览器
    //资源拥有者完成对客户端授权后，授权服务器在浏览器中将用户重定向到客户端的重定向URI，应用需要监听这个回调，并处理来自授权服务器的响应
    function handleOpenURL(url){ //这个监听器会监听com.oauhtinaction.mynativeapp:/上传的请求，并且从URI中取出请求参数
        setTimout(function(){
            processCallback(url.substr(url.indexof('?') + 1));
        }, 0);
    }
    var whitelist = ['code', 'state'];
    callbackData = {};
    h.split('&').forEach(function(e){
        var d = e.split('=');

        if(whitelist.indexOf(d[0]) > -1){
            callbackData[d[0]] = d[1];
        }
    })

    if(callbackData.state !== localStorage.getItem('oauth-state')){
        callbackDate = null;
        $('.oauth-protected-resource').text('Error: state value did not match');
    }
    //使用后端信道向授权服务器发起HTTP请求获取令牌
    $.ajax({
        url: authServer.tokenEndpoint,
        type: 'POST',
        crossDomain: true,
        dataType: 'json',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        data: {
            grant_type: 'authorization_code',
            code: callbackData.code,
            client_id: client.client_id,
            client_secret: client.client_secret,
        }
    }).done(function(data){
        $('.oauth-access-token').text(data.access_token);
        callbackData.access_token = data.acess_token;
    }).fail(function(){
        $('.oauth-protected-resource').text('Error while getting the access token');
    });

处理密钥

客户端密钥的作用是让客户端软件实例向授权服务器进行身份认证，与资源拥有者的授权无关。Web应用可以配置客户端密钥，并向浏览器和最终用户保密，但原生应用和浏览器应用做不到这一点

配置期间密钥在客户端的每个副本中都相同，客户端密钥属于配置期间密钥；运行时密钥，在各个客户端实例都不同。浏览器客户端、原生应用都属于公开客户端不需要客户端密钥；Web应用属于保密客户端需要客户端密钥