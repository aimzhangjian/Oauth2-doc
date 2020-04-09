构建简单OAuth授权服务器
======================================

授权服务器是OAuth生态系统中最复杂的组件，它是整个OAuth系统中安全权威中心，只有授权服务器能够对用户进行认证，注册客户端，颁发令牌。OAuth2.0规范制定中已经尽可能将复杂性从客户端和受保护资源转移至授权服务器

管理OAuth客户端注册
--------------------------------------

向授权服务器注册客户端信息，可以开发web界面维护客户端信息，也可以初始化。这里我们使用静态注册便于观察学习::

    var clients = [
    {
        "client_id": "oauth-client-1",
        "client_secret": "oauth-client-secret-1",
        "redirect_uris": ["http://localhost:9000/callback"],
    }
    ];
    var getClient = function(clientId){
        return __.find(clients, function(client){return client.client_id == clientId;})
    }

对客户端授权
--------------------------------------

OAuth授权要求授权服务器提供两个端点：授权端点，运行在前端信道上；令牌端点，运行在后端信道上

授权端点

用户在OAuth授权过程中第一站是授权端点，授权端点是一个前端信道端点，客户端会将用户浏览器重定向至该端点，以发出授权请求::

    app.get("/authorize", function(req, res){
        var client = getClient(req.query.client_id);
        if(!client){
            console.log("Unknown client %s", req.query.client_id);
            res.render('error', {error: 'Unknow client'});
            return;
        } else if(!__.contains(client.redirect_uris, req.query.redirect_uri)){
            console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
            res.render('error', {error: 'Invalid redirect URI'});
            return;
        } else {
            var reqid = reandomstring.generate(8);
            requests[reqid] = req.query;
            res.render('approve', {client: client, reqid: reqid});
            return;
        }
    });

客户端授权::

    app.post('/approve', function(req, res){
        var reqid = req.body.reqid;
        var query = requests[reqid];
        delete requests[reqid];
        if(!query){
            res.render('error', 'No matching authorization request');
            return;
        }
        if(req.body.approve){
            if(query.response_type == 'code'){
                var code = randomstring.generate(8);
                codes[code] = {request: query};
                var urlParsed = buildUrl(query.redirect_uri, {
                    code: code,
                    state: query.state
                });
                res.redirect(urlParsed);
                return;
            } else {
                var urlParsed = buildUrl(query.redirect_uri, {
                    error: 'unsupported_response_type'
                });
                res.redirect(urlParsed);
                return;
            }
        }
    });

令牌颁发

客户端拿到授权码后，向授权服务器的令牌端点发送POST请求，去访问令牌

对客户端进行身份认证、处理授权许可请求::

    app.post("/token", function(req, res){
        //  获取客户端凭证
        var auth = req.headers['authorization'];
        if(auth){
            var clientCredentials = decodeClientCredentials(auth);
            var clientId = clientCredentials.id;
            var clientSecret =clientCredentials.secret;
        }
        if(req.body.client_id){
            if(clientId){
                console.log('Client attempte to authenticate with multiple methods');
                res.status(401).json({error: 'invalid_client'});
                return;
            }
            var clientId = req.body.client_id;
            var clientSecret = req.body.client_secret;
        }
        //从数据库加载客户端
        var client = getClient(clientId);
        if(!client){
            console.log('Unknown client %s', clientId);
            res.status(401).json({error: 'invalid_client'});
            return;
        }
        if(req.body.grant_type == 'authorization_code'){//判断授权类型
            var code = codes[req.body.code];            //获取之前生成授权码时存储的信息
            if(code){
                delete codesp[req.body.code];           //去除使用过的授权码
                if(code.rquest.client_id == clientId){  //判断获取token客户端是不是对应授权码客户端
                    var access_token = randomstring.generate();
                    nosql.insert({access_token: access_token, client_id: clientId});
                    console.log('Issuing access token %s', access_token);
                    var token_response = {access_token: access_token, token_type: 'Bearer'};
                    res.status(200).json(token_response);
                    console.log('Issued token for code %s', req.body.code);
                    return;
                } else {
                    console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
                    res.status(400).json({error: 'invalid_grant'});
                    return;
                }
            } else {
                console.log('Unknown code, %s', req.boy.code);
                res.status(400).json({error: 'invalid_grant'});
                return;
            }
        } else {
            console.log('Unknown grant type %s', req.body.grant_type);
            res.status(400).json({error: 'unsupported_grant_type'});
        }
    });

支持刷新令牌:

    app.post("/token", function(req, res){
        //  获取客户端凭证
        var auth = req.headers['authorization'];
        if(auth){
            var clientCredentials = decodeClientCredentials(auth);
            var clientId = clientCredentials.id;
            var clientSecret =clientCredentials.secret;
        }
        if(req.body.client_id){
            if(clientId){
                console.log('Client attempte to authenticate with multiple methods');
                res.status(401).json({error: 'invalid_client'});
                return;
            }
            var clientId = req.body.client_id;
            var clientSecret = req.body.client_secret;
        }
        //从数据库加载客户端
        var client = getClient(clientId);
        if(!client){
            console.log('Unknown client %s', clientId);
            res.status(401).json({error: 'invalid_client'});
            return;
        }
        if(req.body.grant_type == 'authorization_code'){//判断授权类型
            var code = codes[req.body.code];            //获取之前生成授权码时存储的信息
            if(code){
                delete codesp[req.body.code];           //去除使用过的授权码
                if(code.rquest.client_id == clientId){  //判断获取token客户端是不是对应授权码客户端
                    var access_token = randomstring.generate();
                    nosql.insert({access_token: access_token, client_id: clientId});
                    console.log('Issuing access token %s', access_token);
                    var token_response = {access_token: access_token, token_type: 'Bearer'};
                    res.status(200).json(token_response);
                    console.log('Issued token for code %s', req.body.code);
                    return;
                } else {
                    console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
                    res.status(400).json({error: 'invalid_grant'});
                    return;
                }
            } else {
                console.log('Unknown code, %s', req.boy.code);
                res.status(400).json({error: 'invalid_grant'});
                return;
            }
        }  else if(req.body.grant_type == 'refresh_token'){
            nosql.one(function(token){
                if(token.refresh_token == req.body.refresh_token){
                    return token;
                }
            }, function(err, token){
                if(token){
                    console.log('We found a matching refresh token: %s', req.body.refresh_token);
                    if(token.clinet_id != clientId){
                        nosql.remove(function(found){return (found == token)}, function(){});
                        res.status(400).json({error: 'invalid_grant'});
                        return;
                    }
                    var access_token = randomstring.generate();
                    nosql.insert({access_token: access_token, client_id: clientId});
                    var token_response = {access_token: access_token, token_type: 'Bearer', refresh_token: token.refresh_token};
                    res.status(200).json(token_response);
                } else {
                    console.log('No matching token was found.');
                    res.status(400).json({error: 'invalid_grant'});
                    return;
                }
            })
        } else {
            console.log('Unknown grant type %s', req.body.grant_type);
            res.status(400).json({error: 'unsupported_grant_type'});
        }
    });

增加授权范围支持

OAuth2.0很重要的机制就是权限范围。首先通常需要限制每个客户端在服务器上可访问范围，防止客户端不当行为，使得系统能限制客户端只能在受保护资源上执行特定操作，我们需要为客户端添加scope字段，存储客户端权限范围，权限之间以空分割，之所以要使用空格分割，而不是使用数组等复杂结构，是因为HTTP表单和查询参数没有一种很好的方式表示像数组和对象这样的复杂结构，然而OAuth又需要使用查询参数通过前端信道来传达信息。
