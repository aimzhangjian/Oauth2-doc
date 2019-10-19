# 保护Web应用
Spring Security是为基于Spring的应用程序提供声明式安全保护的安全性框架。Spring Security提供完整的安全性解决方案，能够在Web请求级别和方法调用级别处理身份认证和授权，充分利用依赖注入和面向切面技术。Spring Securigy从两个角度解决安全性问题，使用Servlet规范中的Filter保护Web请求并限制URL级别的访问；使用Spring AOP保护方法调用，借助于对象代理和使用通知，能够确保只有具备适当权限的用户才能访问安全保护的方法

## 理解Spring Security的模块
Spring Security 3.2一共分为11个模块，应用程序的类路径下至少要包含核心和配置这两个模块：
- ACL：支持通过访问控制列表为域对象提供安全性
- 切面：当使用Spring Security注解时，会使用基于AspectJ的切面，而不是使用标准的Spring AOP
- CAS客户端：提供与Jasig的中心认证服务进行集成的功能
- 配置：包含通过XML和Java配置Spring Security的功能支持
- 核心：提供Spring Security基本库
- 加密：提供加密和密码编码的功能
- LDAP：支持基于LDAP进行认证
- OpenID：支持使用OpenID进行集中是认证
- Remoting：提供了对Spring Remoting的支持
- 标签库：Spring Security的JSP标签库
- Web：提供Spring Security基于Filter的Web安全性支持
## 过滤Web请求
Spring Security借助一系列Servlet Filter来提供各种安全性功能，我们只需配置一个Filter就可以实现。DelegatingFilterProxy是一个特殊的Servlet Filter，他将工作委托给一个javax.servlet.Filter实现类，这个实现类作为一个<bean>注册在spring应用上下文中
### 通过web.xml配置
```xml
    <filter>
        <filter-name>springSecurityFilterChain</filter-name>
        <filter-class>
            org.springframework.web.filter.DelegatingFilterProxy
        </filter-class>
    </filter>
```
DelegatingFilterProxy将过滤逻辑委托给springSecurityFilterChain
### 以Java方式配置
借助WebApplicationInitializer以Java方式配置DelegatingFilterProxy
```java
    public class SecurityWebInitializer extends AbstractSecurityWebApplicationInitializer{

    }
```
AbstractSecurityWebApplicationInitializer实现了WebApplicationInitializer,Spring会用它在Web容器中注册DelegatingFilterProxy。也可以重载appendFilters()或insertFilters()方法来注册自己选择的Filter。不管通过web.xml还是Java方式配置DelegatingFilterProxy，它都会拦截发往应用的请求，并将请求委托给ID为springSecurityFilterChain bean。

springSecurityFilterChain本身是另一个特殊的Filter，它被称为FilterChainProxy，它可以链接任意一个或多个其他的Filter,Spring Security依赖一系列Servlet Filter来提供不同的安全特性，但是几乎不需要知道这些细节，不需要显示申明springSecurityFilterChain以及它所连接在一起的其他Filter

### 编写简单的安全性配置
Spring Security最简单的Java配置
```java
    @Configuration
    @EnableWebSecurity
    public class SecurityConfig extends WebSecurityConfigurerAdapter{

    }
```
@EnableWebSecurity注解用于启动Web安全功能，Spring Security必须配置在一个实现了WebSecurityConfiger的bean中，或者扩展了WebSecurityConfigurerAdapter

如果使用Spring MVC开发则可以使用@EnableWebMvcSecurity替代它，注解还配置了一个Spring MVC参数解析器，这样处理器方法能够通过带有@AuthenticationPrincipal注解的参数获得认证用户的principal，他同时还配置了一个bean，在使用Spring表单绑定标签库来定义表单时，这个bean会自动添加一个隐藏的跨站请求伪造token输入域。

我们可以通过重载WebSecurityConfigurerAdapter的三个configure()方法来配置Web安全性
- configure(WebSecurity)：通过重载，配置Spring Security的Filter链
- configure(HttpSecurity)：通过重载，配置如何通过拦截器保护请求
- configure(AuthenticationManagerBuilder)：通过重载，配置user-detail服务

默认configure(HttpSecurity)实现
```java
    protected void configure(HttpSecurity http) throw Exception{
        http
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .formLogin().and()
            .httpBasic();
    }
```
为了使Spring Security满足我们的需求我们需要
- 配置用户存储
- 指定那些请求需要认证，那些请求不需要认证，以及所需要的权

## 选择查询用户详细信息的服务
Spring Security能够基于各种数据库存储来认证用户，它内置了多种常见的用户存储场景，如内存、关系型数据库以及LDAP，也可编写并插入自定义的用户存储实现

### 使用基于内存的用户存储
通过重载WebSecurityConfigurerAdapter的configure(AuthenticationManagerBuilder)方法，AuthenticationManagerBuilder方法可以用来配置Spring Security对认证的支持，通过inMemoryAuthentication()方法，可以开启、配置并任意填充基于内存的用户存储
```java
    @Configuration
    @EnableWebMvcSecurity
    public void SecurityConfig extends WebSecurityConfigurerAdapter{
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throw Exception{
            auth
            .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER").and()
                .withUser("admin").password("password").roles("USER", "ADMIN");
        }
    }
```
roles()方法是authorities()方法的简写形式，roles()方法所给的值会添加一个“ROLE_”前缀，并将其作为权限授予给用户。withUser()方法返回的是UserDetailsManagerConfigurer.UserDetailsBuider,这个对象设置了多个进一步配置用户的方法
- accountExpired(boolean)：定义账号是否已经过期
- accountLocked(boolean)：定义账号是否已经锁定
- and()：用来连接配置
- authorities(GrantedAuthority...)：授予某个用户一项或多项权限
- authorities(List<? extends GrantedAuthority>)：授予某个用户一项或多项权限
- authorities(String...)：授予某个用户一项或多项权限
- credentialsExpired(boolean)：定义凭证是否已经过期
- disabled(boolean)：定义账号是否已被禁用
- password(String)：定义用户密码
- roles(String...)：授予某个用户一项或多项角色
对于调试和开发人员测试来讲，基于内存的用户存储很有用，但对于生产环境最好选择某种类型的数据库
### 基于数据库表进行认证
用户数据通常会存储在关系型数据库中，并通过JDBC进行访问，为配置Spring Security使用以JDBC为支撑的用户存储，可以使用jdbcAuthentication()方法
```java
    @Autowired
    DataSource dataSource

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth
            .jdbcAuthentication()
            .dataSource(dataSource);
    }
```
#### 重写默认的用户查询功能
Spring Security预期存在某些存储用户数据的表，内置查找用户信息时所执行的SQL如下：
```java
    public static final String DEF_USERS_BY_USERNAME_QUERY = 
        "select username,password,enabled " +
        "from users " +
        "where username = ?";
    public static final String DEF_AUTHORITOES_BY_USERNAME_QUERY = 
        "select username,authority "+
        "from authorities "+
        "where username = ?";
    public static final String DEF_AUTHORITIES_BY_USERNAME_QUERY = 
        "select g.id, g.group_name, ga.authority "+
        "from groups g, group_members gm, group_authorities ga "+
        "where gm.username = ? " +
        "and g.id = ga.gorup_id " +
        "and g.id = gm.group_id";
```

替换内置查询sql，使用自定义查询sql
```java
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth
            .jdbcAuthtication()
            .userByUsernaneQuery(
                "select username, password, true " +
                "from Spitter where username = ?")
            .authoritiesByUsernameQuery(
                "select username, 'ROLE_USER' from Spitter where username = ?");
            .groupAuthoritiesByUsername("...");
    }
```
将默认的SQL查询替换为自定义的设计时，很重要的一点就是要遵循查询的基本协议，所有查询都将用户名作为唯一的参数
#### 使用转码后的密码
数据库中用户密码通常都是进行转码存储的，Spirng Security需要借助passwordEncoder()方法指定一个密码转换器
```java
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth
            .jdbcAuthentication()
            .usersByUsernameQuery(
               "select username, password, true " +
                "from Spitter where username = ?")
            .authoritiesByUsernameQuery(
                "select username, 'ROLE_USER' from Spitter where username = ?");
            .groupAuthoritiesByUsername("...")
            .passwordEncoder(new StandardPasswordEncoder("53cr3t"));
    }
```
passwordEncoder()方法可以接受Spring Security中PasswordEncoder接口的任意实现，Spring Security的加密模块包括了三个这样的实现：BCryptPasswordEncoder、NoOpPasswordEncoder和StandardPasswordEncoder

如果内置的实现无法满足需求时，可以提供自定义实现PasswordEncoder接口
```java
    public interface PasswordEncoder{
        String encode(CharSequence rawPassword);
        boolean matches(CharSequence rawPassword, String encodedPassword);
    }
```
### 基于LDAP进行认证
为了让Spring Security使用基于LDAP的认证，可以使用ldapAuthentication()方法
```java
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth
            .ldapAuthentication()
                .userSearchFilter("(uid = {0})")·
                .groupSearchFilter("member = {0}");
    }
```
userSearchFilter()和groupSearchFilter()用来为基础LDAP查询提供过滤条件，他们分别用于搜索用户和组，默认用户和组的基础查询都是空的，搜索会在LDAP层级结构的根开始，可以通过如下方式改变默认行为
```java
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth
            .ldapAuthentication()
            .userSearchBase("ou=pople") //指定从名为people的组织单元下搜索
            .userSearchFilter("(uid={0})")
            .groupSearchBase("ou=groups") //指定从名为groups的组织单元下搜索
            .groupSearchFilter("member={0}")
    }
```
#### 配置密钥比对
基于LDAP进行认证的默认策略是进行绑定操作，直接通过LDAP服务器认证用户。另一种方式是进行比对操作，需要将输入密码发送到LDAP目录上，并要求服务器将这个密码和用户密码进行比对。通过密码比对进行认证
```java
    @Override
    protected void configure(AuthenticationManagerBuilder auth){
        auth
            .ldapAuthentication()
                .userSearchBase("ou=people")
                .userSearchFilter("(uid={0})")
                .groupSearchBase("ou=groups")
                .groupSearchFilter("member={0}")
                .passwordCompare();
    }
```
默认情况下，登录表单中提供的密码会与用户LDAP条目中的userPassword属性进行比对，如果密码保存在不同的属性中，可以通过passwordAttribute()方法来声明密码属性的名称
```java
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .ldapAuthentication()
                .userSearchBase("ou=people")
                .userSearchFilter("(uid = {0})")
                .groupSearchBase("ou=groups")
                .groupSearchFilter("member = {0}")
                .passwordCompare()
                .passwordEncoder(new Md5PasswordEncoder())
                .passwordAttribute("passcode");
    }
```
#### 引用远程LDAP服务器
默认情况下Spring Security的LDAP认证假设LDAP服务器监听本机33389端口。我们也可以通过contextSource()配置远程LDAP服务器
```java
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .ldapAuthentication()
                .userSearchBase("ou=people")
                .userSearchFilter("(uid = {0})")
                .groupSearchBase("ou = gourps")
                .groupSearchFilter("member = {0}")
                .contextSource()
                    .url("ldap://habuma.com:389/dc=habuma,dc=com")
    }
```
### 配置自定义用户服务
我们需要认证的用户数据可能存储在非关系型数据库中，这种情况下我们需要提供一个自定义的UserDetailsService接口实现
```java
    public interface UserDetailsService{
        UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
    }
```
我们所要做的就是实现loadUserByUsername()方法,根据给定的用户名来查找用户
```java
    public class SpitterUserService implements UserDetailsService{
        private final SpitterRepository spitterRepository;

        public SpitterUserService(SpitterRepository spitterRepository){
            this.spitterRepository = spitterRepository;
        }

        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
            Spitter spitter = spitterRepository.findByUsername(username);
            if(spitter != null){
                List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
                authorities.add(new SimpleGrantedAuthority("ROLE_SPITTER"));
                return new User(
                    spitter.getUsername(),
                    spitter.getPassword(),
                    authorities
                );
            }
            throw new UsernameNotFoundException("User: " + username + " not found");
        }
    }
```
为了使用SpitterUserService来认证用户，可以通过userDetailsService()方法设置到安全配置中。userDetailsService()方法会配置一个用户存储。另一种方案是实现UserDetails，这样就可以直接返回实现UserDetails的对象
```java
    @Authowired
    SpitterRepository spitterRepository;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .userDetailsService(new SpitterUserService(spitterRepository));
    }
```
## 拦截请求
适当的安全性控制是必要的。对每个请求进行细粒度安全性控制的关键在于重载configure(HttpSecurity)方法
```java
    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
            .authorizeRequests()
                .antMatchers("/spitters/me").authenticated()
                .antMatchers("HttpMethod.POST", "/spittles").authenticated()
                .anyRequest().permitAll();
    }
```
HttpSecurity对象可以在多个方面配置HTTP的安全性，通过调用authorizeRequests()方法返回的对象的方法配置请求级别的安全性细节
- antMatchers()：路径支持Ant风格的通配符，也可以在方法中指定多个路径
- regexMatchers()：接受正则表达式来定义请求路径
- authenticated()：要求执行该请求时，必须已经登陆了应用，如果用户没有认证，Spring Security的Filter将会捕获该请求，并将用户重定向到应用的登陆页面
- permitAll()：允许请求没有任何的安全限制
- access(String)：如果给定的SpEL表达式计算结果为true，就允许访问
- anonyMous()：允许匿名用户访问
- denyAll()：无条件拒绝所有访问
- fullyAuthenticated()：如果用户是完整认证，而不是通过Rememer-me功能认证，就允许访问
- hasAnyAuthority(String...)：如果用户具备给定权限中的某一个的话，就允许访问
- hasAnyRole(String...)：如果用户具备给定角色中的某一个，就允许访问
- hasAuthority(String)：如果用户具备给定权限，就允许访问
- hasIpAddress(String)：如果请求来自给定IP地址，就允许访问
- hasRole(String)：如果用户具备给定角色，就允许访问，自定使用“ROLE_”前缀
- not()：对其他访问方法的结果求反
- rememberMe()：如果用户是通过remember-me功能进行认证的，就允许访问
这些规则会按照给定的顺序发挥作用，因此我们需要将最为具体的请求路径放在前面，最不具体的路径放在后面，不然不具体的路径配置将会覆盖更为具体的路径
### 使用Spring表达式进行安全保护
借助access()方法我们可以将SpEL作为声明式访问限制的一种方法，Spring Security支持的SpEL表达式
- authentication：用户的认证对象
- denyAll：结果始终为false
- hasAnyRole(list of roles)：如果用户被授予了列表中任意的指定角色，结果为true
- hasRole(role)：如果用户被授予了指定的角色，结果为true
- hasIpAddress(IP Address)：如果请求来自指定的IP，结果为true
- isAnonymous()：如果当前用户为匿名用户，结果为true
- isAuthenticated()：如果当前用户进行了认证，结果为true
- isFullyAuthenticated()：如果当前用户进行了完整认证，而不是Remember-me功能进行认证，结果为true
- isRememberMe()：如果当前用户是通过Remember-me自动认证，结果为true
- permitAll：结果始终为true
- principal：用户的principal对象
```java
    .antMatchers("/spitter/me")
        .access("hasRole('ROLE_SPITTER') and hasIpAddress('192.168.1.2')")
```
### 强制通道的安全性
通过requiresChannel()方法，可以为各种URL模式声明所要求的通道
- requiresSecure()：会自动把请求重定向到HTTPS上
- requiresInsecure()：会把请求重定向到不安全的HTTP通道上
```java
    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
            .authorizeRequests()
                .antMatchers("/spitter/me").hasRole("SPITTER")
                .antMatchers(HttpMethod.POST, "/spittles").hasRole("SPITTER")
                .anyRequest().permitAll()
            .and()
            .requiresChannel()
                .antMatchers("/spitter/form").requiresSecure()
                .antMatchers("/").requiresInecure();

    }
```
### 防止跨站请求伪造
从Spring Security 3.2开始，默认开启CSRF防护，通过一个同步token的方式来实现CSRF防护功能，它会拦截状态变化的请求并检查CSRF token，如果请求中不包含CSRF token或者token不能与服务器端的token相匹配，请求将会失败，并抛出CsrfException异常。Spring Security简化了将token放入请求属性中这一任务，如果使用Thymeleaf作为页面模版，只要<form>标签的action属性添加了Thymeleaf命名空间前缀，那么就会自动生成一个“_csrf”隐藏域
```html
    <form method = "POST" th:action = "@{/spittles}">
        ...
    </form>
```
使用JSP作为页面模板
```html
    <input type = "hidden"
            name = "${_csrf.parameterName}"
            value = "${_csrf.token}" />
```
使用Spring表单绑定标签，<sf:form> 标签会自动为我们添加隐藏的SCRF token标签

关闭CSRF防护功能
```java
    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
            ...
            .csrf()
                .disable(); //禁止CSRF防护功能
    }
```
## 认证用户

### 启用HTTP Basic认证
HTTP Basic认证会直接通过HTTP请求本身，对要访问应用程序的用户进行认证。本质上这是一个HTTP 401响应，表明必须要在请求中包含一个用户名和密码，在REST客户端向它使用的服务端进行认证的场景中，比较合适
- httpBasic()：开启HTTP Basic认证
- realmName()：指定域
```java
    @Override
    protected void configure(HttpSecurity http) throw Exception{
        http
            .formLogin()
                .loginPage("/login")
            .and()
            .httpBasic()
                .realmName("Spittr")
    }
```
### 启用Remember-me功能
Spring Security通过rememberMe()方法开启Remember-me功能
```java
    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
            .fromLogin()
                .loginPage("/login")
            .and()
            .rememberMe()
                .tokenValiditySeconds(2419200) //设置token有效时间
                .key("spittrKey"); //设置私钥名为spittrKey，默认为SpringSecured
    }
```
默认情况下这个功能是通过在cookie中存储一个token完成，默认两周内有效，存储在cookie中的token包含用户名、密码、过期时间和一个私钥。

Remember-me功能开启后，我们需要一种方式来让用户表明希望应用程序能够记住他们，为了实现这一点，需要请求必须包含一个名为Remember-me的参数
```html
    <input id = "remember_me" name = "remember-me" type = "checkbox"/>
    <label for = "remember_me" class = "inline">Remember me</label>
```
### 退出
退出功能是通过Servlet容器中的Filter实现的，这个Filter会拦截针对“/logout”的请求。Spring Security的LogoutFilter会拦截处理发起“/logout”的请求，用户会退出应用，所有的Remember-me token都会被清除，用户浏览器将重定向到“/login?logout”,允许用户再次登录
```html
    <a th:href = "@{/logout}">Logout</a>
```
可以配置用户退出将页面重定向到其它页面
```java
    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
            .formLogin()
                .loginPage("/login")
            .and()
            .logout()
                .logouSuccessUrl("/")
    }
```
通过logoutUrl()重写默认LogoutFilter拦截器路径
```java
    .logout()
        .logoutSuccessUrl("/")
        .logoutUrl("signout")
```



# springboot对security的支持
Spring Boot针对Spring Security的自动配置在org.springframework.boot.autoconfigure.security包中。主要通过SecurityAutoConfiguration和SecurityProperties来完成配置。SecurityAutoConfiguration导入SpringBootWebSecurityConfiguration中的配置，在SpringBootWebSecurityConfigoration配置中，获得如下的自动配置
- 自动配置了一个内存中的用户，账号为user，密码在程序启动时出现
- 忽略/css/**、/js/**、/images/**和/**/favicon.ico等静态文件的拦截
- 自动配置的securityFilterchainRegistration的Bean

SecurityProperties使用以“security”为前缀的属性配置Spring Security相关的配置
```
    security.user.name=user #内存中的用户，默认是账号为user
    security.user.password= #默认用户的密码
    security.user.role=USER #默认用户的角色
    security.require-ssl=false #是否需要ssl支持
    security.enable-csrf=false #是否开启“跨站请求伪造”支持，默认关闭
    security.basic.enabled=true
    security.basic.realm=Spring
    security.basic.path=
    security.basic.authorize-mode=
    security.filter-order=0
    security.headers.xss=false
    security.headers.cache=false
    security.headers.frame=false
    security.headers.content-type=false
    security.headers.hsts=all
    security.sessions=stateless
    security.ignore= #用逗号隔开的无须拦截的路径
```

通过继承WebSecurityConfigurerAdapter类，可扩展自己的配置
```java
    @Configuration
    public class WebSecurityConfig extends WebSecurityConfigurerAdapter{

    }
```
## 实战
新建Spring Boot项目，依赖为JPA、Security、Thymeleaf

1. 添加依赖

2. 添加配置文件application.properties
```properties
    spring.datasource.driverclassName=
    spring.datasource.url=
    spring.datasource.username=
    spring.datasource.password=
    logging.level.org.springframwork.security= INFO
    spring.thymeleaf.cache=false
    spring.jpa.hibernate.ddl-auto= update
    spring.jpa.show-sql= true
```
3. 用户和角色
```java
    /**
    *实现UserDetails接口
    *
    */
    @Entity
    public class SysUser implements UserDetails{
        private static final long serialVersionUID = 1L;
        @Id
        @GeneratedValue
        private Long id;
        private String username;
        private String password;
        @ManyToMany(cascade = {CascadeType.REFRESH}, fetch = FetchType.EAGER)
        private List<SysRole> roles;

        /**
        *重写getAuthorities()方法，将角色作为权限
        *
        */
        @Override
        public Collection<? extends GrantedAuthority> getAuthorities(){
            List<GrantedAuthority> auths = new ArrayList<GrantedAuthority>();
            List<SysRole> roles = this.roles;
            for(SysRole role:roles){
                auths.add(new SimpleGrantedAuthority(role.getName()));
            }
            return auths;
        }

        @Override
        public boolean isAccountNonExpired(){
            return true;
        }

        @Override
        public boolean isAccountNonLocked(){
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired(){
            return true;
        }

        @Override
        public boolean isEnabled(){
            return true;
        }

        //省略getter、setter方法
    }


    @Entity
    public class SysRole{
        @ID
        @GeneratedValue
        private Long id;

        private String name;
        //省略getter、setter方法
    }

    /**
    *传值对象
    *
    */
    public class Msg{
        private String title;
        private String conten;
        private String etraInfo;
        public Msg(String title, String content, String etraInfo){
            super();
            this.title = title;
            this.content = content;
            this .etraInfo = etraInfo;
        }
        //省略getter、setter方法
    }
```
4. 数据访问
```java
    public interface SysUserRepository extends JpaRepository<SysUser, Long>{
        SysUser findByUsername(String username);
    }
```
5. 自定义UserDetailsService
```java
    /**
    *自定义实现UserDetailsService接口
    *
    */
    public class CustomUserService implements UserDetailsService{
        @Autowired
        SysUserRepository userRepository;

        /**
        *重写loadUserByUsername方法获得用户
        *
        */
        @Override
        public UserDetails loadUserByUsername(String username){
            SysUser user = userRepository.findByUsername(username);
            if(user == null){
                throw new UsernameNotFoundException("用户名不存在")
            }
            return user;
        }
    }
```
6. Spring MVC配置
```java
    @Configuration
    public class WebMvcConfig extends WebMvcConfigurerAdapter{
        @Override
        public void addViewControllers(ViewContollerRegistry registry){
            registry.addViewController("/login").setViewName("login");
        }
    }
```
7. Spring Security配置
```java
    @Configuration
    public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
        @Bean
        UserDetailsService customUesrService(){
            return new CustomUserService();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception{
            auth.userDetailsService(customUserService());
        }

        @Override
        protected void configure(HttpSecutity http) throws Exception{
            http
                .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .formLogin()
                        .loginPage("/login")
                        .failureUrl("/login?error")
                        .permitAll() //定制登录行为，登录页面可任意访问
                    .and()
                    .logout().permitAll(); //定制注销行为，注销请求可任意访问
        }
    }
```