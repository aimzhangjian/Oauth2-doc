构建简单的OAuth受保护资源
======================================

资源服务器需要从传入的HTTP请求中解析出OAuth令牌，验证令牌，并确定它能用于那些请求

解析HTTP请求中的OAuth令牌::

    var getAccessToken = function(req, res, next){
        var inToken = null;
        var auth = req.headers['authorization'];
        if(auth && auth.toLowerCase().indexOf('bearer') == 0){
            inToken = auth.slice('bearer'.length);
        } else if(req.body && req.body.access_token){
            inToken = req.body.access_token;
        } else if(req.query && req.query.access_token){
            inToken = req.query.access_token;
        }
    };

存储验证令牌
--------------------------------------
令牌存储方式:

 - 共享数据库

 - 令牌内省Web协议，由授权服务器提供接口，让资源服务器能够在运行时检查令牌状态

 - 令牌内包含受保护资源能直接解析并理解的信息，JWT就是这样一种数据结构，可以使用受加密的JSON对象携带声明信息

验证令牌::

    var getAccessToken = function(req, res, next){
        var inToken = null;
        var auth = req.headers['authorization'];
        if(auth && auth.toLowerCase().indexOf('bearer') == 0){
            inToken = auth.slice('bearer'.length);
        } else if(req.body && req.body.access_token){
            inToken = req.body.access_token;
        } else if(req.query && req.query.access_token){
            inToken = req.query.access_token
        }
        console.log('Incoming token: %s', inToken);
        nosql.one(function(token){
            if(token.access_token == inToken){
                return token;
            }
        }, function(err, token){
            if(token){
                console.log('We found a matching token: %s', inToken);
            } else {
                console.log('No matching token was found.');
            }
            req.access_token = token;
            next();
            return;
        })
    };

根据令牌提供内容::

    var requireAccessToken = function(req, res, next){
        if(req.access_token){
            next();
        } else {
            res.status(401).end();
        }
    };

不同权限范围对应不同操作::

    app.get('/words', getAccessToken, requireAccessToken, function(req, res){
        if(__.contains(req.access_token.scope, 'read')){
            res.json({words: savedWords.join(' '), timestamp: Data.now()});
        } else {
            res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error = "insufficient_scope", scope = "read"');
            res.status(403);
        }
    });

    app.post('/words', getAccessToken, requireAccessToken, function(req, res){
        if(__.contains(req.access_token.scope, 'write')){
            if(req.body.word){
                savedWords.push(req.body.word);
            }
            res.stastus(201).end();
        } else {
            res.set('WWW-Authenticate', 'Bearer realm = localhost:9002, error = "insufficient_scope", scope = "write"')
            res.status(403);
        }
    });

    app.delete('/words', getAccessToken, requireAccessToken, function(req, res){
        if(__.contains(req.access_token.scope, 'delete')){
            savedWord.pop();
            res.status(204).end();
        } else {
            res.set('WWW-Authenticate', 'Bearer realm = location:9002, error = "insufficient_scope", scope = "delete"')
        }
    });

不同权限范围对应不同数据结果::

    app.get('/produce', getAccessToken, requireAccessToken, function(req, res){
        var produce =  {fruit: [], veggies: [], meats: []};
        if(__.contains(req.access_token.scope, 'fruit')){
            produce.fruit = ['apple', 'banana', 'kiwi'];
        }
        if(__.contains(req.access_token.scope, 'veggies')){
            produce.veggies = ['lettuce', 'onion', 'potato'];
        }
        if(__.contains(req.access_token.scope, 'meats')){
            produce.meats = ['bacon', 'steak', 'chicken breast'];
        }
    });

不同用户对应不同数据结果::

    app.get('/favorites', getAccessToke, requireAccessToken, function(req, res){
       if(req.access_token.user == 'alice'){
           res.json({user: 'Alice', favorites: aliceFavorites});
       } else if(req.access_token.user == 'bob'){
           res.json({user: 'Bob', favorites: bobFavorites});
       } else {
           var unknow = {user: 'Unknown', favorites: {movies:[], foods: [], music: []}};
           res.json(unknown);
       }
    });