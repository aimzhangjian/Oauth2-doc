# 构建OAuth客户端

## 向授权服务器注册OAuth客户端
1. 客户端标识符：用来标识OAuth客户端，在OAuth协议的多个组件都称其为client_id。在一个给定的授权服务器中，每个客户端的标识符必须唯一，因此客户端标识符总是由授权服务器分配，可以通过开发者门户完成，也可以通过动态客户端注册

2. 共享密钥：client_secret用于客户端与授权服务器交互时进行身份认证

## 授权码许可类型获取令牌
使用授权码许可类型的交互授权形式，有客户端将资源拥有者重定向到授权服务器的授权端点，然后服务器通过redirect_uri将授权码返回给客户端，最后客户端将收到的授权码发送给授权服务器的令牌端点，换取OAuth访问令牌

### 发送授权请求
```javascript
    var client = {
        "client_id": "oauth-client-1",
        "client-secret": "oauth-client-secret-1",
        "redirect_uris": ["http://localhost:9000/callback"]
    };

    var authServer = {
        authorizationEndpoint: 'http://localhost:9001/authorize',
        tokenEndpoint: 'http://localhost:9001/token'
    };

    var buildUrl = function(base, options, hash){
        var newUrl = url.parse(base, ture);
        delete newUrl.search;
        if(!newUrl.query) {
            newUrl.query = {};
        }
        __.each(options, function(value, key, list){
            newUrl.query[key] = value;
        });
        if(hash){
            newUrl.hash = hash;
        }
        return url.format(newUrl);
    };

    app.get('/authorize', function(req, res){
        access_toke = null;
        state = randomstring.generate();
        var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
            response_type: 'code',
            client_id: client.client_id,
            redirect_uri: cllient.redirect_uris[0],
            state: state
        });

        console.log("redirect", authorizeUrl);
        res.redirect(authorizeUrl)
    });
```
真正的OAuth客户端应用绝不因该使用像这样的能从外部访问的触发机制，而是因该跟踪内部应用状态，用于确定何时需要请求新的访问令牌

### 处理授权响应
```javascript
    app.get('/callback', function(req, res){
        if(req.query.error){
            res.render("error", {error: req.query.error});
            return;
        }
        if(req.query.state != state){
            console.log('State DOES NOT MATCH: expeted %s got %s', state, req.query.state);
            res.render("error", {error: 'State value did not match'});
            return;
        }
        var code = req.query.code;
        var form_date = qs.stringify({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: client.redirect_uris[0]
        });
        var headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic' + encodeClientCredentials(client.client_id, client.client_secret)
        };
        var tokRes = request('POST', authServer.tokenEndpoint, {
            body: form_data,
            headers: headers
        })
        console.log('Requesting access token for code %s', code);
        if(tokRes.statusCode >= 200 && tokRes.statusCode < 300){
            var body = JSON.parse(tokRes.getBody);
            access_token = body.access_token;
            console.log('Got access token: %s', access_token);
            res.render('index', {access_token: access_token, scope: scope});
        } else {
            res.render('error', {error: 'Unable to fetch access token, server response:' + tokRes.statusCode})
        }
    });
```

### state参数添加跨站保护
防止攻击者向授权服务器暴力搜索有效的授权码，浪费客户端和授权服务器资源，以及导致客户端获取一个从未请求过的令牌，可以使用state可选OAuth参数来缓解这个问题，将该参数设置为一个随机值，并在应用中用一个变量保存。将state添加到通过授权端点URL发送的参数列表中。当授权服务器收到state参数的授权请求时，他必须总是将该state参数和授权码一起原样返回给客户端。客户端可以比较返回的status与原值是否一致，如果不一致向最终用户提示错误。

### 使用令牌访问受保护资源
客户端要访问受保护资源只需要使用令牌向受保护资源发出调用请求，有3个合法的位置可以用于携带令牌
1. 使用HTTP Authorization头部，这是规范推荐尽可能使用的方法，最灵活、最安全

2. 使用表单格式请求体参数
- 限制受保护资源只能接收表单格式的输入参数，并且要使用POST方法

3. 使用URL编码的查询参数
- 可能被无意地泄露到服务器日志中，应为查询参数是URL请求的一部分

获取受保护资源
```javascript
    app.get('/fetch_resource', function(req, res){
        if(!access_token){
            res.render('error', {error: 'missiong Access Token'});
        }
        console.log('Making request with access token %s', access_token);
        var headers = {
            'Authorization': 'Bearer' + access_token
        };
        var resource = request('POST', protectedResource, {headers: headers});
        if(resource.statusCode >= 200 && resource.statusCode < 300){
            var body = JSON.parse(resource.getBody());
            res.render('data', {resource: body});
            return;
        } else {
            access_token = null;
            res.render('error', {error: resource.statusCode});
            return; 
        }
    });
```
### 刷新访问令牌

```javascript
    app.get('/fetch_resource', function(req, res){
        console.log('Making request with access token %s', access_token);
        var headers = {
            'Authorization': 'Bearer' + access_token,
            'Content-type': 'application/x-www-form-urlencoded'
        }
        var resource = request('POST', protectedResource, {headers: headers})
        if(resource.statusCode >= 200 && resource.statusCode < 300){
            var body = JSON.parse(resource.getBody());
            res.render('data', {resource: body});
            return;
        } else {
            access_token = null;
            if(refresh_token){
                refreshAccessToken(req, res);
                return;
            } else {
                res.render('error', {error: resource.statusCode});
                return;
            }
        }
    });

    var refreshAccessToken = function(req, res){
        var form_data = qs.stringify({
            grant_type: 'refresh_token',
            refresh_token: refresh_token
        });
        var headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic' + encodeClientCredentials(client.client_id, client.client_secret)
        };
        console.log('Refreshing token %s', refresh_token);
        var tokRes = request('POST', authServer.tokenEndpoint,{
            body: form_data,
            headers: headers
        })
        if(tokRes.statusCode >= 200 && tokRes.statusCode < 300){
            var body = JSON.parse(tokRes.getBody());
            access_token = body.access_token;
            console.log('Got access token: %s', refresh_token);
            if(body.refresh_token){
                refresh_token = body.refresh_token;
                console.log('Got refresh token: %s', refresh_token);
            }
            scope = body.scope;
            console.log('Got scope: %s', scope);
            res.redirect('/fetch_resource');
            return;
        } else {
            console.log('No refresh token, asking the user to get a new access token');
            refresh_token = null;
            res.render('error', {error: 'Unable to refresh token.'});
            return;
        }
    }
```


