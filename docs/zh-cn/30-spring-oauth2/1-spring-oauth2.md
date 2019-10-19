# Spring OAuth2
OAuth2协议在Spring Resource中的实现为Spring OAuth2。Spring OAuth2分为OAuth2 Provider和OAuth2 Client

## OAuth2 Provider
OAuth2 Provider负责公开被OAuth2保护起来的资源。OAuth2 Provider需要配置代表用户的OAuth2客户端信息，通过管理和验证OAuth2令牌来控制客户端是否可以访问受保护资源，同时还必须为用户提供认证API接口

OAuth2 Provider的角色被分为Authorization Service（授权服务）和Resurce Service（资源服务）。所有获取令牌的请求都将会在Spring MVC controller endpoints中处理，并且访问受保护资源服务的处理流程将会放在标准Spring Security请求过滤器中

配置一个授权服务必须要实现以下endpoints
- AuthorizationEndpoint：用来作为请求者获得授权的服务，默认URL为/oauth/authorize
- TokenEndpoint：用来作为请求者获得令牌的服务，默认URL为/oauth/token

配置一个资源服务必须要实现的过滤器
- OAuth2AuthenticationProcessingFilter：用来作为认证令牌的一个处理流程过滤器，只有当过滤器通过之后，请求者才能获取受保护资源

### Authorization Server配置
配置Authorization Server时，需要考虑客户端从用户获取访问令牌的类型（authorization_code：授权码类型；password：密码模式；client_credentials：客户端模式；implicit：简化模式；refresh_token：刷新access_token）。Authorization Server需要配置客户端的详细信息和令牌服务的实现

继承AuthenticationServerConfigurerAdapter在类上添加@EnableAuthorizationServer注解，开启Authorization Server功能，注入到IOC容器中，并实现以下配置
- ClientDetailsServiceConfigurer：配置客户端信息
- AuthorizationServerEndpointsConfigurer：配置授权Token的节点和Token服务
- AuthorizationServerSecurityConfigurer：配置Token节点的安全策略

#### 配置客户端详情

ClientDetailsServiceConfigurer。客户端配置信息既可以放在内存中，也可以放在数据库中，需要配置如下信息。可以通过实现ClientDetailService接口管理
- clientId：客户端Id，唯一
- secret：客户端密码
- scope：客户端的域，用来限制客户端的访问范围，如果为空，客户端拥有全部的访问权限
- authorizedGrantTypes：认证类型
- authorities：权限信息

#### 管理令牌

AuthorizationServerTokenServices接口定义了一些操作使得可以对令牌进行一些必要的管理，请注意以下几点
- 当一个令牌被创建，必须对其进行保存，这样当一个客户端使用这个令牌对资源服务进行请求的时才能引用这个令牌
- 当一个令牌是有效的，可以被用来加载身份信息，里面包含这个令牌的相关权限
我们可以使用DefaultTokenServices类，这个类实现了AuthorizationServerTokenServices接口，可以使用其提供的方法来修改令牌格式和令牌存储。默认创建令牌时使用随机值来进行填充，除了持久化令牌是委托TokenStore接口来实现外，这个类几乎做了所有的事情。TokenStore实现
- InMemoryTokenStore：默认实现，存储在内存中
- JdbcTokenStore：基于JDBC的实现版本，令牌会存储在关系型数据库中
- JwtTokenStore：令牌相关数据进行编码，但其撤销一个已经授权令牌会很困难，通常用来处理
一个生命周期较短的令牌已经撤销刷新令牌
- RedisTokenStore：令牌存储在redis中

#### 配置授权类型

授权使用AuthorizationEndpoint端点进行控制，可以使用AuthorizationServerEndpointsConfigurer对象实例进行配置，默认开启了所有验证类型，除了密码类型的验证，需要配置authenticationManager才能开启
- authorizationCodeServices：设置授权码服务（即AuthorizationCodeServices的实例对象），主要用于“authorization_code”授权码类型模式
- tokenStore：设置令牌存储类型，默认内存存储
- userDetailsSercice：如果注入了一个UserDetailsService,refresh token grant将对用户状态进行校验，以保证用户处于激活状态
- authenticationManager：通过注入AuthenticationManager启用密码授权模式
- redirectResolver：配置重定向解析器，实现RedirectResolver接口
- tokenGranter：TokenGranter完全控制授予流程并忽略上面的其他属性

#### 配置授权端点的URL
AuthorizaitonServerEndpointsConfigurer可以通过pathMapping()方法来配置端点URL链接，它有两个参数
- 第一个参数：String类型，这个端点URL的默认链接
- 第二个参数：String类型，需要替换成的URL链接
以上字符串都以“/”字符开始的字符串，框架的默认URL链接如下列表
- /oauth/authorize：授权端点
- /oauth/token：令牌端点
- /oauth/confirm_access：用户确认授权提交端点
- /oauth/error：授权服务错误信息端点
- /oauth/check_token：用户资源服务访问的令牌解析端点
- /oauth/token_key：提供公有密钥的端点，如果使用JWT令牌

#### 强制使用SSL
通过Spring Security的requiresChannel约束来保证安全，是否启用SSL可以通过AuthorizationServerEndpointsConfigurer配置对象的sslOnly()方法来设置。如果设置强制使用SSL Spring Security会把不安全的请求通道重定向到一个安全通道。AuthorizationServerSecurityConfigurer源码
```java
    public AuthorizationServerSecurityConfigurer sslOnly() {
        this.sslOnly = true;
        return this;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {

        registerDefaultAuthenticationEntryPoint(http);
        if (passwordEncoder != null) {
            ClientDetailsUserDetailsService clientDetailsUserDetailsService = new ClientDetailsUserDetailsService(clientDetailsService());
            clientDetailsUserDetailsService.setPasswordEncoder(passwordEncoder());
            http.getSharedObject(AuthenticationManagerBuilder.class)
                    .userDetailsService(clientDetailsUserDetailsService)
                    .passwordEncoder(passwordEncoder());
        }
        else {
            http.userDetailsService(new ClientDetailsUserDetailsService(clientDetailsService()));
        }
        http.securityContext().securityContextRepository(new NullSecurityContextRepository()).and().csrf().disable()
                .httpBasic().realmName(realm);
        if (sslOnly) {
            http.requiresChannel().anyRequest().requiresSecure();
        }
    }
```
### 资源服务配置
一个资源服务提供一些受token令牌保护的资源，Spring OAuth提供者是通过Spring Security authentication filter即验证过滤器来实现保护，可以通过@EnableResourceServer注解到一个@Configuration配置类，并且必须使用ResourceServerConfigurer这个配置对象来进行配置，可以选择继承ResourceServerConfigureAdapter然后复写其中的方法
- tokenServices：ResourceServerTokenServices类的实例，实现令牌服务
- resourceId：这个资源服务的ID，这个属性是可选的，但推荐设置并在授权服务中进行验证
- 其他的拓展属性例如tokenExtractor令牌提取器用来提取请求中的令牌
- 请求匹配器，用来设置需要进行保护的资源路径，默认情况下是受保护资源服务的全路径
- 受保护资源的访问规则，默认规则是简单的身份认证
- 其他的自定义权限保护规则通过HttpSecurity来进行配置
@EnableResourceServer注解自动增加一个类型为OAuth2AuthenticationProcessingFilter的过滤器链

```java
    @Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private SecurityProperties properties;
    @Autowired(required = false)
    private ResourceMatcher resourceMatcher;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        if (properties.isCustomResourceMatcher() && resourceMatcher != null) {
            http
                .requestMatcher(resourceMatcher)
                .authorizeRequests()
                .anyRequest().authenticated();
        } else {
            http
                .antMatcher("/api/**")
                .authorizeRequests()
                .anyRequest().authenticated();
        }
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId("default");
    }
}
```

ResourceServerTokenServices是组成授权服务的另一半，如果你的授权服务和资源服务在同一个应用程序上，可使用DefaultTokenServices
