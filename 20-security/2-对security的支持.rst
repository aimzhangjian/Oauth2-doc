springboot对security的支持
======================================

Spring Boot针对Spring Security的自动配置在org.springframework.boot.autoconfigure.security包中。主要通过SecurityAutoConfiguration和SecurityProperties来完成配置。SecurityAutoConfiguration导入SpringBootWebSecurityConfiguration中的配置，在SpringBootWebSecurityConfigoration配置中，获得如下的自动配置:

 - 自动配置了一个内存中的用户，账号为user，密码在程序启动时出现

 - 忽略/css/**、/js/**、/images/**和/**/favicon.ico等静态文件的拦截

 - 自动配置的securityFilterchainRegistration的Bean

SecurityProperties使用以“security”为前缀的属性配置Spring Security相关的配置::

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

通过继承WebSecurityConfigurerAdapter类，可扩展自己的配置::

    @Configuration
    public class WebSecurityConfig extends WebSecurityConfigurerAdapter{

    }

实战
--------------------------------------

新建Spring Boot项目，依赖为JPA、Security、Thymeleaf

1. 添加依赖

2. 添加配置文件application.properties::


    spring.datasource.driverclassName=
    spring.datasource.url=
    spring.datasource.username=
    spring.datasource.password=
    logging.level.org.springframwork.security= INFO
    spring.thymeleaf.cache=false
    spring.jpa.hibernate.ddl-auto= update
    spring.jpa.show-sql= true

3. 用户和角色::


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

4. 数据访问::


    public interface SysUserRepository extends JpaRepository<SysUser, Long>{
        SysUser findByUsername(String username);
    }

5. 自定义UserDetailsService::


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

6. Spring MVC配置::


    @Configuration
    public class WebMvcConfig extends WebMvcConfigurerAdapter{
        @Override
        public void addViewControllers(ViewContollerRegistry registry){
            registry.addViewController("/login").setViewName("login");
        }
    }

7. Spring Security配置::


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