OAuth令牌
======================================

OAuth令牌是什么
--------------------------------------

令牌是OAuth事务的核心。令牌表示的是授权行为的结果：一个信息元组，包括资源拥有者、客户端、授权服务器、受保护资源、权限范围以及其他与授权决策有关的信息

OAuth核心规范不对令牌本身做任何规定，使得OAuth能广泛的适用于各种部署场景。令牌可以与授权用户关联或者系统中所有用户关联，也可以不代表任何用户，令牌可以有内部结构，也可以是随机的无意义字符串。

对于令牌存储在共享数据库中的情况，当受保护资源接收客户端令牌后会去用户中查找令牌，令牌本身不携带任何信息。对于非共享数据库情况，可以让令牌本身携带信息，而不用通过请求接口或查询数据库查找令牌信息。

结构化令牌：JWT
--------------------------------------

通过将所有必要的信息放到令牌内部，使得授权服务可以通过令牌本身间接与保护资源沟通。

JWT的结构

JSON Web令牌格式，或者叫JWT，提供一种在令牌中携带信息的简单方法，JWT的核心将一个JSON对象封装为一种用于网络传输的格式，通过句点分割令牌字符串，句点符号之间的值是一个经过Base64URL编码的JSON对象::

    eyJoeXAioiJKV1QiLCJhbGciOiJub251In0.eyJzdWIioiIxMjM0NTY3oDkwIiwibmFtZSI6IkpvaG4gRG91IiwiYRtaW4iOnRydwv9.

其中第一部分表示::

    {
        "type": "JWT",
        "alg": "none"
    }

这是JWT头部，type头告诉处理程序令牌第二部分是何种类型，alg头值为none表示一个未签名的令牌

JWT声明

标准JSON Web令牌声明:
 - iss：令牌颁发者，表示令牌由谁创建，在很多OAuth部署中会将它设为授权服务器的URL，该声明是一个字符串
 - sub：令牌主体，表示令牌是关于谁的，在很多OAuth部署中会将它设为资源拥有者的唯一标识。该声明是一个字符串
 - aud：令牌受众，表示令牌接收者，在很多OAuth部署中，它包含受保护资源的URI或者能够接收该令牌的受保护资源。该声明可以是一个字符串数组，如果只有一个值，也可以是一个不用数组包装的单个字符串
 - exp：令牌过期时间戳，他表示令牌将在何时过期，以便部署应用让令牌自行失效，该声明是一个整数，表示自UNIX新纪元（1970.1.1零点）以来的秒数
 - nbf：令牌生效时的时间戳，表示令牌什么时候开始生效，该声明为一个整数，表示UNIX新纪元以来的秒数
 - iat：令牌颁发时的时间戳，表示令牌是何时被创建的，该声明是一个整数，表示自UNIX新纪元以来的秒数
 - jti：令牌的唯一标识符，该令牌的值在令牌颁发者创建的每一个令牌中都是唯一的，为防止冲突，它通常是一个密码学随机值这个值相当于向结构化令牌中加入了一个攻击者无法获取的随机熵组件，有利于防止令牌猜测攻击和重放攻击

我们也可以在其中添加其他所需字段

在服务器上实现JWT

要创建JWT，首先需要一个头部，指明该令牌是JWT且不带签名::

    var header = {'type': 'JWT', 'alg': 'none'}

接下来创建一个对象来承载JWT载荷，并根据我们所关心的令牌信息来指定字段::

    var payload = {
        iss: 'http://localhost:9001/',
        sub: code.user ? code.user.sub : undefined,
        aud: 'http://localhost:9002/',
        iat: Math.floor(Date.now()/1000),
        exp: Math.floor(Date.now()/1000) + (5 * 60),
        jti: randomstring.generate(8)
    }

将头部和载荷的JSON序列化为字符串，并对他们进行Base64URI编码，以句点符号作为连接符将他们连接起来::

    var access_token = base64url.encode(JSON.stringify(header))
    + '.'
    + base64url.encode(JSON.stringify(payload))
    + '.';

资源服务器从传入的令牌中获取信息，执行授权服务器令牌创建流程的逆操作来解析令牌：按照句点符号将字符串分开，得到不同部分，然后将第二部分从Base64URL解码，解析出一个JSON对象::

    var tokenParts = inToken.split('.');
    var payload = JSON.parse(base64url.decode(tokenParts[1]));

这样就得到了一个能在应用内进行检查的原生数据结构，我们要确保该令牌来自预期的颁发者；时间戳在合适的范围内；资源服务器是预期的令牌接收者::

    if(payload.iss == 'http://localhost:9001/'){
        if((Array.isArray(payload.aud) && __.contains(payload.aud, 'http://localhost:9002/')) || payload.aud == 'http://localhost:9002/'){
            var now = Math.floor(Date.now() / 1000);
            if(payload.iat <= now){
                if(payload.exp >= now){
                    req.access_token = payload;
                }
            }
        }
    }

令牌的加密保护：JOSE
--------------------------------------

使用JSON对象的签名和加密标准对JWT结构令牌进行加密，这套规范以JSON为基础数据模型，提供了签名（JSON Web签名，或称JWS）、加密（JSON Web加密，或称JWE）以及密钥存储格式（JSON Web密钥，或称JWK）的标准。使用HMAC签名方案的对称签名和验证，以及使用RSA签名方案的非对称签名和验证，使用JWK来存储RSA公钥和私钥

为了完成繁重的加密任务，我们会使用一个叫JSRSASign的JSON库，这个库提供了基本的签名和密钥管理功能，但不提供加密功能

使用HS256的对称签名::

    var sharedTokenSecret = 'shared OAuth token secret!';

使用这个密钥对令牌签名，修改头部参数，指定签名方法为HS256::

    var header = {'type': 'JWT', 'alg': 'HS256'};

JOSE库要求在向签名函数传入数据前先进行JSON序列化（但不进行Base64URL编码），使用JOSE库和共享密钥对令牌进行HMAC签名算法，由于JOSE库的特殊需求，需要传入十六进制字符串形式的共享密钥，其他的库会对密钥格式有不同要求::

    var access_token = jose.jws.JWS.sign(header.alg, 
        JSON.stringify(header),
        JSON.stringify(payload),
        new Buffer(sharedTokenSecret).toString('hex'));

头部和载荷还是和之前一样，经过Base64URL编码的JSON字符串，签名被放在JWT格式的最后一个句点符号后面，是经过Base64URL编码的一组字节，签名JWT的整体结构为header.payload.signature

修改受保护资源，让其能验证令牌的签名::

    var sharedTokenSecret = 'shared OAuth token secret!';

首先，解析令牌::

    var tokenParts = inToken.split('.');
    var header = JSON.parse(base64url.decode(tokenParts[0]));
    var payload = JSON.parse(base64url.decode(tokenParts[1]));

这一次要用到令牌头部，接下来要根据共享密钥来验证签名，这是我们对令牌内容的首次检查，我们使用的库要求在验证前将密钥转换成十六进制字符串格式::

    if(jose.jws.JWS.verify(inToken,new Buffer(sharedTokenSecret).toString('hex'), [header.alg])){


使用RS256的非对称签名

如上在使用共享密钥时，创建签名和验证签名的系统使用同一个密钥，这样授权服务器和资源服务器都能生产令牌。使用公钥加密，授权服务器拥有公钥和私钥，可用于生成令牌，而受保护资源则只能访问授权服务器的公钥，用于验证令牌，但无法自己生成有效的令牌，我们使用JOSE库中的RS256签名方法，它的地层使用RSA算法

首先需要在授权服务器上添加一对公钥和私钥，我们的密码对是2048位的RSA密钥，这是推荐的最小长度，本练习使用基于JSON的JWK来存储密钥，可以通过JOSE库直接读取::

    RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
    jwk.setKeyId("authserver");
    final String publicKeyString = jwk.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    final String privateKeyString = jwk.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);

使用私钥和RS256非对称签名方法，对内容进行签名::

    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setIssuer("authserver");  //设置颁发者
    jwtClaims.setAudience("Audience");  //设置受众
    jwtClaims.setExpirationTimeMinutesInTheFuture(10); //过期时间
    jwtClaims.setGeneratedJwtId();  //令牌唯一标识，通常是一个密码学随机数
    jwtClaims.setIssuedAtToNow();   //令牌颁发时的时间
    jwtClaims.setNotBeforeMinutesInThePast(2); //代码生效时的时间
    jwtClaims.setSubject("aim");     //资源拥有者的唯一表标识
    jwtClaims.setStringClaim("payload", payload);
    jwtClaims.setStringClaim("header", header);

    JsonWebSignature jws = new JsonWebSignature();
    jws.setPayload(jwtClaims.toJson());
    jws.setKey(jwk.getRsaPrivateKey());   //私钥
    jws.setKeyIdHeaderValue(jwk.getKeyId());
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256); //指定签名算法

    String jwt = jws.getCompactSerialization();

使用公钥和RS256非对称签名方法，对签名进行验签::

    JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setExpectedIssuer("authserver")    //期望的颁发者
                .setExpectedAudience("Audience")    //期望的令牌接收者
                .setVerificationKey(jwk.getRsaPublicKey())  //验签公钥
                .setJweAlgorithmConstraints(new AlgorithmConstraints    (AlgorithmConstraints.ConstraintType.WHITELIST,
                        AlgorithmIdentifiers.RSA_USING_SHA256)) //指定验签算法
                .build();

    JwtClaims jwtClaims2 = jwtConsumer.processToClaims(jwt);

其他令牌保护方法

基于JOSE的保护令牌方法提供了多种。然而仅签名是不够的，对于仅被签名的令牌，客户端还是可以偷窥令牌本身，从中获取它本无权知道的信息，除了签名之外，JOSE还提供了一个叫JWE的加密机制，包含几种不同的选项和算法，经过JWE加密的JWT不再只有3部分组成，而是由5部分组成。各个部分仍然使用Base64URL编码，只是载荷现在变成了一个经过加密的对象，没有正确的密钥无法读取其内容

首先私钥签名::

    //生成签名密钥对
    RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
    jwk.setKeyId("authserver");

    //私钥签名
    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setIssuer("authserver");
    jwtClaims.setAudience("Audience");
    jwtClaims.setExpirationTimeMinutesInTheFuture(10);
    jwtClaims.setGeneratedJwtId();
    jwtClaims.setIssuedAtToNow();
    jwtClaims.setNotBeforeMinutesInThePast(2);
    jwtClaims.setSubject("token");
    jwtClaims.setStringClaim("payload", payload);
    jwtClaims.setStringClaim("header", header);

    JsonWebSignature jws = new JsonWebSignature();
    jws.setPayload(jwtClaims.toJson());
    jws.setKey(jwk.getRsaPrivateKey());
    jws.setKeyIdHeaderValue(jwk.getKeyId());
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

    String jwt = jws.getCompactSerialization();

然后公钥对签名内容加密::

    //生成密钥对
    RsaJsonWebKey jwk2 = RsaJwkGenerator.generateJwk(2048);
    jwk2.setKeyId("encryption");
    //对签名内容加密
    JsonWebEncryption jwe3 = new JsonWebEncryption();
    jwe3.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
    jwe3.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
    jwe3.setKey(jwk2.getRsaPublicKey());
    jwe3.setPayload(jwt);
    String token1 = jwe3.getCompactSerialization();

私钥对加密内容解密::

    //对签名内容解密
    JsonWebEncryption jwe4 = new JsonWebEncryption();
    jwe4.setKey(jwk2.getPrivateKey());
    jwe4.setCompactSerialization(token1);
    String jwt2 = jwe4.getPayload();

公钥对签名内容验签::

    //公钥验签
    JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime()
            .setAllowedClockSkewInSeconds(30)
            .setRequireSubject()
            .setExpectedIssuer("authserver")
            .setExpectedAudience("Audience")
            .setVerificationKey(jwk.getRsaPublicKey())
            .setJweAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                    AlgorithmIdentifiers.RSA_USING_SHA256))
            .build();

    JwtClaims jwtClaims2 = jwtConsumer.processToClaims(jwt2);

在线获取令牌信息：令牌内省
--------------------------------------

将令牌信息打包放入令牌本身，将导致令牌尺寸变得非常大，如果受保护资源完全依赖令牌本身所包含的信息，则一旦将有效的令牌生成并发布，想要撤回会非常困难

内省协议

OAuth令牌内省协议定义了一种机制，让受保护资源能够主动向授权服务器查询令牌状态。该协议是对OAuth的一个简单增强。授权服务器向客户端颁发令牌，客户端向受保护资源出示令牌，受保护资源向授权服务器查询令牌状态

内省请求是发送给授权服务器内省端点的表单形式的HTTP请求，受保护资源在请求过程中需要向授权服务器进行身份认证，内省协议并未规定如何认证，例如，受保护资源使用ID和密码通过HTTP Basic进行省份认证，这与OAuth客户端向令牌端点进行身份认证方式一样。也可以使用单独的访问令牌完成此过程，UMA协议就是这样做的。

内省请求的响应是一个JSON对象，用于描述令牌信息，它的内容与JWT的载荷相使，任何有效的JWT声明都可以包含在响应中::

    HTTP 200 ok
    Content-type: application/json
    {
        "active": true,
        "scope": "foo bar baz",
        "client_id": "oauth-client-1",
        "username": "alice",
        "iss": "http://localhsot:9001/",
        "sub": "alice",
        "aud": "http://localhsot:9002/",
        "iat": 1440538696,
        "exp": 1440538996,
    }

内省协议规范还在JWT的基础上增加了几个声明定义，其中最重要的是active声明，此声明告诉受保护资源当前令牌在授权服务器上是否有效，且是唯一必须返回的声明。由于OAuth令牌有多种部署类型，对有效令牌的定义并没有标准。但一般情况下，它的含义为令牌是由该授权服务颁发，还没有过期，也没有撤回，而且允许当前受保护资源获取它的信息。使用令牌内省会导致OAuth系统内的网络流量增加，为解决这个问题，允许受保护资源缓存给定令牌的内省请求结果，建议设置短于令牌生命周期的缓存有效期，以降低令牌被撤回但缓存还有效的可能性。
