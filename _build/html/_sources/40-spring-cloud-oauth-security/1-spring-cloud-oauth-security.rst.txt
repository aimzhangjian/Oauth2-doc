Spring Cloud OAuth Security
======================================

实战Spring Cloud整合OAuth、Security
--------------------------------------

1. 创建Spring Boot项目hzero-oauth，添加主要依赖如下::

    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-starter-oauth2</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-starter-security</artifactId>
    </dependency>

2. 新建配置文件application.yml文件，配置项目信息

3. 配置授权服务必须要配置的endpoints，依赖的jar包有默认提供，可拷贝复制出来，覆盖默认实现，添加自己的实现::

 - AuthorizationEndpoint：用来为请求者获取授权的服务，默认URL是/oauth/authorize

 - TokenEndpoint：用来作为请求者获取令牌的服务，默认URL是/oauth/token

4. 实现Spring Security UserDetailsService接口用于身份认证

