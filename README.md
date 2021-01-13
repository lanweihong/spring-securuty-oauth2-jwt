# 微服务中使用Spring Security + OAuth 2.0 + JWT 搭建认证授权服务

**OAuth** 是一种用来规范令牌（Token）发放的授权机制，主要包含了四种授权模式：授权码模式、简化模式、密码模式和客户端模式。关于 OAuth 更多介绍可访问 [理解OAuth 2.0](http://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html) 查看。本文主要以 **密码模式** 来实现用户认证和授权。

## 搭建项目

本例项目以微服务为基础，仅实现认证服务和资源服务，其他如网关、服务管理、配置中心等省略，本文重点是使用 Spring Security + OAuth 2.0 + JWT 实现用户认证授权。

项目结构如下图，认证服务和资源服务分离，认证服务主要是提供令牌和校验令牌服务。

![项目结构](https://public-image-lwh.oss-cn-shenzhen.aliyuncs.com/spring-security-oauth2.0/project.png)

父工程 `pom.xml` 配置如下，主要是指定依赖包的版本：

```xml
    <!-- 依赖包版本管理 -->
    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <spring.boot.version>2.2.2.RELEASE</spring.boot.version>
        <spring.cloud.version>Hoxton.SR9</spring.cloud.version>
        <spring.cloud.alibaba.version>2.2.1.RELEASE</spring.cloud.alibaba.version>
        <mysql.driver.version>8.0.16</mysql.driver.version>
        <lombok.version>1.16.18</lombok.version>
        <druid.version>1.1.10</druid.version>
    </properties>

    <dependencyManagement>

        <dependencies>

            <!-- spring boot 2.2.2.RELEASE -->
            <dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-dependencies</artifactId>
                <version>2.2.2.RELEASE</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>

            <!-- spring cloud -->
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>${spring.cloud.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>

            <!-- Spring Cloud Alibaba -->
            <dependency>
                <groupId>com.alibaba.cloud</groupId>
                <artifactId>spring-cloud-alibaba-dependencies</artifactId>
                <version>${spring.cloud.alibaba.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>

            <!-- mysql driver -->
            <dependency>
                <groupId>mysql</groupId>
                <artifactId>mysql-connector-java</artifactId>
                <version>${mysql.driver.version}</version>
            </dependency>

            <!-- lombok -->
            <dependency>
                <groupId>org.projectlombok</groupId>
                <artifactId>lombok</artifactId>
                <version>${lombok.version}</version>
            </dependency>

            <!-- druid -->
            <dependency>
                <groupId>com.alibaba</groupId>
                <artifactId>druid-spring-boot-starter</artifactId>
                <version>${druid.version}</version>
            </dependency>

        </dependencies>

    </dependencyManagement>
```

## 搭建认证服务

### 引入依赖

1. 在 `pom.xml` 引入以下依赖：

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-oauth2</artifactId>
</dependency>
        
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>

<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>druid-spring-boot-starter</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-jdbc</artifactId>
</dependency>

<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
</dependency>
```

`spring-cloud-starter-oauth2`  已经包含了 `spring-cloud-starter-security`、`spring-security-oauth2`、`spring-security-jwt` 这3个依赖，只需引入 `spring-cloud-starter-oauth2` 即可。

2. 编辑 `application.yml`，添加数据库连接参数：

```yml
spring:
  datasource:
    type: com.alibaba.druid.pool.DruidDataSource
    url: jdbc:mysql://127.0.0.1:3307/oauth_server?useUnicode=true&characterEncoding=utf8&zeroDateTimeBehavior=convertToNull&useSSL=false&serverTimezone=Asia/Shanghai
    username: root
    password: 1
    druid:
      driver-class-name: com.mysql.cj.jdbc.Driver
      initial-size: 5
      max-active: 50
      max-wait: 60000
      min-idle: 5
```

### 准备工作

1. 新建 `UserDTO` 类，实现 `org.springframework.security.core.userdetails.UserDetails` 接口；

```java
/**
 * @author lanweihong 986310747@qq.com
 */
@Data
public class UserDTO implements Serializable, UserDetails {
    private static final long serialVersionUID = 5538522337801286424L;

    private String userName;
    private String password;
    private Set<SimpleGrantedAuthority> authorities;

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    public String getPassword() {
        return this.password;
    }

    public String getUsername() {
        return this.userName;
    }

    public boolean isAccountNonExpired() {
        return true;
    }

    public boolean isAccountNonLocked() {
        return true;
    }

    public boolean isCredentialsNonExpired() {
        return true;
    }

    public boolean isEnabled() {
        return true;
    }
}
```

2. 新建类 `UserDetailsServiceImpl`，实现 `org.springframework.security.core.userdetails.UserDetailsService` 接口，用于校验用户凭据。

```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private PasswordEncoder passwordEncoder;

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // TODO 实际开发中，这里请修改从数据库中查询...
        UserDTO user = new UserDTO();
        user.setUserName(username);
        // 密码为 123456 ，且加密
        user.setPassword(passwordEncoder.encode("123456"));
        return user;
    }
}
```

以上用户配置用于测试，任意用户名，但密码为 **123456**，实际生产中务必修改为从数据库中读取校验。

### 配置认证授权服务器

1. 新建类 `Oauth2ServerConfig`，继承 `org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter` 类；在 `Oauth2ServerConfig` 类上 添加注解 `@EnableAuthorizationServer` 。

 框架提供了几个默认的端点：

 - `/oauth/authorize`：授权端点
 - `/oauth/token`：获取令牌端点
 - `/oauth/confirm_access`：用户确认授权端点
 - `/oauth/check_token`：校验令牌端点
 - `/oauth/error`：用于在授权服务器中呈现错误
 - `/oauth/token_key`：获取 jwt 公钥端点

2. 继承 `AuthorizationServerConfigurerAdapter` 类后，我们需要重写以下三个方法扩展实现我们的需求。

 - `configure(ClientDetailsServiceConfigurer clients)` ：用于定义、初始化客户端信息

 - `configure(AuthorizationServerEndpointsConfigurer endpoints)`：用于定义授权令牌端点及服务

 - `configure(AuthorizationServerSecurityConfigurer security)`：用于定义令牌端点的安全约束

#### 配置客户端详细信息

`ClientDetailsServiceConfigurer`  用于定义 **内存** 中或  **基于JDBC存储实现** 的客户端，其重要的几个属性有：

 - `clientId`：客户端id，必填；
 - `clientSecret`：客户端密钥；
 - `authorizedGrantTypes`：客户端授权类型，有 *5* 种模式： `authorization_code`、`password`、`client_credentials`、`implicit`、`refresh_token`；
 - `scope`：授权范围；
 - `accessTokenValiditySeconds`：`access_token` 有效时间，单位为秒，默认为 *12* 小时；
 - `refreshTokenValiditySeconds`：`refresh_token` 有效时间，单位为秒，默认为 *30* 天；

客户端信息一般保存在 Redis 或 数据库中，本例中客户端信息保存在 MySQL 中；
**基于JDBC存储** 模式需要创建数据表，官方提供了建表的 SQL 语句，可访问  [schema.sql](https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/test/resources/schema.sql) 获取 SQL ；

1. 使用以下 SQL（适用于MySQL） 来建表：
```sql
CREATE TABLE `oauth_client_details`  (
  `client_id` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `resource_ids` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `client_secret` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `scope` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `authorized_grant_types` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `web_server_redirect_uri` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `authorities` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `access_token_validity` int(11) NULL DEFAULT NULL,
  `refresh_token_validity` int(11) NULL DEFAULT NULL,
  `additional_information` varchar(4096) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `autoapprove` varchar(256) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  PRIMARY KEY (`client_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;
```

2. 添加一条客户端信息用于测试：

```sql
INSERT INTO `oauth_client_details` VALUES ('auth-server', NULL, '$2a$10$mcEwJ8qqhk2DYIle6VfhEOZHRdDbCSizAQbIwBR7tTuv9Q7Fca9Gi', 'all', 'password,refresh_token', '', NULL, NULL, NULL, NULL, NULL);
```

其中密码 **123456** 使用 `BCryptPasswordEncoder` 加密，加密后字符为 `$2a$10$mcEwJ8qqhk2DYIle6VfhEOZHRdDbCSizAQbIwBR7tTuv9Q7Fca9Gi`。

3. 配置 `ClientDetailsServiceConfigurer` ，指定客户端信息：

```java
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    private final DataSource dataSource;
    
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public Oauth2ServerConfig(DataSource dataSource, PasswordEncoder passwordEncoder) {
        this.dataSource = dataSource;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // 使用基于 JDBC 存储模式
        JdbcClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
        // client_secret 加密
        clientDetailsService.setPasswordEncoder(passwordEncoder);
        clients.withClientDetails(clientDetailsService);
    }
}
```

#### 配置授权令牌端点及服务

配置 `AuthorizationServerEndpointsConfigurer` 需要指定 `AuthenticationManager` 及 `UserDetailService`，尤其是使用密码模式时，必须指定 `AuthenticationManager`，否则会报 `Unsupported grant type: password` 错误。

1. 新建 `WebSecurityConfig` 类，继承 `org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter` 类，重写 `authenticationManagerBean()` 方法，并定义需要用到的 `PasswordEncoder`；

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // 支持跨域请求
                .cors()

                .and()
                // 禁用 CSRF
                .csrf().disable()

                .formLogin().disable()
                .httpBasic().disable()
                .logout().disable()

                .authorizeRequests()
                .antMatchers("/oauth/token").permitAll();

                .anyRequest().authenticated();
    }

    /**
     * 重写 authenticationManagerBean()
     * @return
     * @throws Exception
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

2. 配置 `AuthorizationServerEndpointsConfigurer`：

```
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    private final UserDetailsServiceImpl userDetailsService;

    /**
     * 密码模式 grant_type:password 需指定 AuthenticationManager
     */
    private final AuthenticationManager authenticationManager;


    @Autowired
    public Oauth2ServerConfig(UserDetailsServiceImpl userDetailsService,
                              AuthenticationManager authenticationManager) {
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                // 开启密码模式授权
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService);
    }
}
```

##### 使用 JWT 作为令牌格式

###### 生成 JWT 密钥对

使用 JDK 的 **keytool** 工具生成 JKS 密钥对 `jwt.jks`，并将 `jwt.jks` 放到 `resources` 目录下。

定位至 JDK 目录下的 `bin` 目录，执行以下命令生成密钥对：
```
keytool -genkey -alias weihong -keyalg RSA -keypass 123456 -keystore jwt.jks -storepass 123456
```

> **参数说明：**
> 
> ```
> -genkey 生成密钥
> 
> -alias 别名
> 
> -keyalg 密钥算法
> 
> -keypass 密钥口令
> 
> -keystore 生成密钥对的存储路径和名称
> 
> -storepass 密钥对口令
> ```

###### 定义 token 转换器

在 `Oauth2ServerConfig` 类中定义 `accessTokenConverter()` 及 `keyPair()`：

```java
    /**
     * token 转换器
     * 默认是 uuid 格式，我们在这里指定 token 格式为 jwt
     * 使用非对称加密算法对 token 签名
     * @return
     */
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        // 使用非对称加密算法对 token 签名
        converter.setKeyPair(keyPair());
        return converter;
    }

    @Bean
    public KeyPair keyPair() {
        // 从 classpath 目录下的证书 jwt.jks 中获取秘钥对
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "lanweihong".toCharArray());
        return keyStoreKeyFactory.getKeyPair("weihong", "lanweihong".toCharArray());
    }
```

###### 指定令牌存储策略为 JWT

配置 `AuthorizationServerEndpointsConfigurer` 的令牌存储策略为 JWT，指定 `accessTokenConverter` 为我们定义好的 `accessTokenConverter()`：

```java
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    private final UserDetailsServiceImpl userDetailsService;

    /**
     * 密码模式 grant_type:password 需指定 AuthenticationManager
     */
    private final AuthenticationManager authenticationManager;

    @Autowired
    public Oauth2ServerConfig(UserDetailsServiceImpl userDetailsService,
                              AuthenticationManager authenticationManager) {
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
    }


    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
                // 开启密码模式授权
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                // 指定令牌存储策略
                .accessTokenConverter(accessTokenConverter());
    }

    /**
     * token 转换器
     * 默认是 uuid 格式，我们在这里指定 token 格式为 jwt
     * @return
     */
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        // 使用非对称加密算法对 token 签名
        converter.setKeyPair(keyPair());
        return converter;
    }

    @Bean
    public KeyPair keyPair() {
        // 从 classpath 目录下的证书 jwt.jks 中获取秘钥对
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "lanweihong".toCharArray());
        return keyStoreKeyFactory.getKeyPair("weihong", "lanweihong".toCharArray());
    }

}    
```

##### 扩展 JWT 存储内容

有时候我们需要扩展 JWT 存储的内容，比如存储一些用户数据、权限信息等。我们可以定义 `TokenEnhancer` 或继承 `TokenEnhancer` 来实现 JWT 内容增强器：

```java
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return (oAuth2AccessToken, oAuth2Authentication) -> {
            Map<String, Object> map = new HashMap<>(1);
            UserDTO userDTO = (UserDTO) oAuth2Authentication.getPrincipal();
            map.put("userName", userDTO.getUsername());
            // TODO 其他信息可以自行添加
            ((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(map);
            return oAuth2AccessToken;
        };
    }
```

配置 `AuthorizationServerEndpointsConfigurer` JWT 内容增强器：

```java
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    private final UserDetailsServiceImpl userDetailsService;

    private final AuthenticationManager authenticationManager;

    @Autowired
    public Oauth2ServerConfig(UserDetailsServiceImpl userDetailsService,
                              AuthenticationManager authenticationManager) {
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> delegates = new ArrayList<>();

        delegates.add(tokenEnhancer());
        delegates.add(accessTokenConverter());

        // 配置 JWT 内容增强
        enhancerChain.setTokenEnhancers(delegates);

        endpoints
                // 开启密码模式授权
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .accessTokenConverter(accessTokenConverter())
                .tokenEnhancer(enhancerChain);
    }
    
    /**
     * token 转换器
     * 默认是 uuid 格式，我们在这里指定 token 格式为 jwt
     * @return
     */
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        // 使用非对称加密算法对 token 签名
        converter.setKeyPair(keyPair());
        return converter;
    }

    @Bean
    public KeyPair keyPair() {
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "lanweihong".toCharArray());
        return keyStoreKeyFactory.getKeyPair("weihong", "lanweihong".toCharArray());
    }
    
    /**
     * JWT 内容增强器，用于扩展 JWT 内容，可以保存用户数据
     * @return
     */
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return (oAuth2AccessToken, oAuth2Authentication) -> {
            Map<String, Object> map = new HashMap<>(1);
            UserDTO userDTO = (UserDTO) oAuth2Authentication.getPrincipal();
            map.put("userName", userDTO.getUsername());
            // TODO 其他信息可以自行添加
            ((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(map);
            return oAuth2AccessToken;
        };
    }
}
```

##### 使用 Redis 存储 token

1. 在 `pom.xml` 中添加依赖：

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

2. 编辑 `application.yml`，添加 Redis 连接参数：

```yml
spring:
  redis:
    host: localhost
    port: 6379
    password: 1
```

3. 添加 token 保存至 redis 的配置:

```java
@Configuration
public class RedisTokenStoreConfig {

    @Resource
    private RedisConnectionFactory connectionFactory;

    @Bean
    public TokenStore redisTokenStore() {
        return new RedisTokenStore(connectionFactory);
    }
}
```

4. 在认证服务配置中指定 token 存储方式：

```java
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    private final UserDetailsServiceImpl userDetailsService;

    /**
     * 密码模式 grant_type:password 需指定 AuthenticationManager
     */
    private final AuthenticationManager authenticationManager;
    
    private final TokenStore tokenStore;

    @Autowired
    public Oauth2ServerConfig(UserDetailsServiceImpl userDetailsService,
                              AuthenticationManager authenticationManager,
                              @Qualifier("redisTokenStore") TokenStore tokenStore) {
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
        this.tokenStore = tokenStore;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                // 开启密码模式授权
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                // 设置 token 存储方式
                .tokenStore(tokenStore);
    }
}
```

#### 配置授权令牌安全约束

```java
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                // 允许表单认证
                .allowFormAuthenticationForClients()
                // 开放 /oauth/token_key 获取 token 加密公钥
                .tokenKeyAccess("permitAll()")
                // 开放 /oauth/check_token
                .checkTokenAccess("permitAll()");
    }
```

#### 认证授权服务配置完整代码

**`Oauth2ServerConfig`：**

```java
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    /**
     * 数据源
     */
    private final DataSource dataSource;

    private final UserDetailsServiceImpl userDetailsService;

    /**
     * 密码模式 grant_type:password 需指定 AuthenticationManager
     */
    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    private final TokenStore tokenStore;

    @Autowired
    public Oauth2ServerConfig(DataSource dataSource,
                              UserDetailsServiceImpl userDetailsService,
                              AuthenticationManager authenticationManager,
                              PasswordEncoder passwordEncoder,
                              @Qualifier("redisTokenStore") TokenStore tokenStore) {
        this.dataSource = dataSource;
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.tokenStore = tokenStore;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security
                // 允许表单认证
                .allowFormAuthenticationForClients()
                // 需通过认证后才能访问 /oauth/token_key 获取 token 加密公钥
                .tokenKeyAccess("permitAll()")
                // 开放 /oauth/check_token
                .checkTokenAccess("permitAll()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // 使用基于 JDBC 存储模式
        JdbcClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
        clientDetailsService.setPasswordEncoder(passwordEncoder);
        clients.withClientDetails(clientDetailsService);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> delegates = new ArrayList<>();

        delegates.add(tokenEnhancer());
        delegates.add(accessTokenConverter());

        // 配置 JWT 内容增强
        enhancerChain.setTokenEnhancers(delegates);

        endpoints
                // 开启密码模式授权
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .accessTokenConverter(accessTokenConverter())
                .tokenEnhancer(enhancerChain)
                // 设置 token 存储方式
                .tokenStore(tokenStore);
    }

    /**
     * token 转换器
     * 默认是 uuid 格式，我们在这里指定 token 格式为 jwt
     * @return
     */
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        // 使用非对称加密算法对 token 签名
        converter.setKeyPair(keyPair());
        return converter;
    }

    @Bean
    public KeyPair keyPair() {
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "lanweihong".toCharArray());
        return keyStoreKeyFactory.getKeyPair("weihong", "lanweihong".toCharArray());
    }

    /**
     * JWT 内容增强器，用于扩展 JWT 内容，可以保存用户数据
     * @return
     */
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return (oAuth2AccessToken, oAuth2Authentication) -> {
            Map<String, Object> map = new HashMap<>(1);
            UserDTO userDTO = (UserDTO) oAuth2Authentication.getPrincipal();
            map.put("userName", userDTO.getUsername());
            // TODO 其他信息可以自行添加
            ((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(map);
            return oAuth2AccessToken;
        };
    }
}
```

**`WebSecurityConfig`：**

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // 支持跨域请求
                .cors()

                .and()
                // 禁用 CSRF
                .csrf().disable()

                .formLogin().disable()
                .httpBasic().disable()
                .logout().disable()

                .authorizeRequests()
                .antMatchers("/oauth/token").permitAll()

                .anyRequest().authenticated();
    }

    /**
     * 重写 authenticationManagerBean()
     * @return
     * @throws Exception
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### 测试获取 token

#### 获取 token

运行项目，使用 **Postman** 访问 `/oauth/token` 端点，并传参数，参数必须与我们配置的内容一致；

![使用Postman测试](https://public-image-lwh.oss-cn-shenzhen.aliyuncs.com/spring-security-oauth2.0/get-token-test.png)

成功获取到 token ，格式如下：````

```json
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTA1NjkzNDksInVzZXJOYW1lIjoiYWRtaW4iLCJ1c2VyX25hbWUiOiJhZG1pbiIsImp0aSI6IjgzM2VjZDdkLThmMzctNDAxOS04YWQwLTBlODI3ZTM4M2U5YyIsImNsaWVudF9pZCI6Im9hdXRoLXNlcnZlciIsInNjb3BlIjpbImFsbCJdfQ.ke6fWfGMOXhppF-6XXftZJx0w8hSnTKYYwvi_As66Ats9_AFqrHCZiuHA_M5LD2bJzahFC__-IUr_6g6ajx-IlLpSPqs3izgbuOPcTzCivfznGn38W5kYPe1ygQ8mJzN97yAT1QKZGMAT0nr7HR5NSG2MHYPbHuWSHp4KVIf7XQbszmXVPKEeQsv64QZ8O1xe9XtshF4mtZsxfLEGxAZEPSkoyJi-vwH6qKnvVh8EI8zgwTX5cIh6Gj4rcEfDiJYNAiI_NanuNA1wBoI1eD-QYSUQ5XXW1Q4vQAnjQMQwvTZYn1hGdAbeHQrA9hPLw5_Axeq8_meWpNobla_rRYkLQ",
    "token_type": "bearer",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJhZG1pbiIsInNjb3BlIjpbImFsbCJdLCJhdGkiOiI4MzNlY2Q3ZC04ZjM3LTQwMTktOGFkMC0wZTgyN2UzODNlOWMiLCJleHAiOjE2MTMxMTgxNDksInVzZXJOYW1lIjoiYWRtaW4iLCJqdGkiOiIwMDljZjhmNy05OTE5LTQyODEtYjUxNS02NjM3ZjIyM2MyN2YiLCJjbGllbnRfaWQiOiJvYXV0aC1zZXJ2ZXIifQ.bFMQRXCOz2rvu8QhTOjjlM66Fe3EM5F2wUXI-3dQOxnu2AOCsCJKUZdT0AhsnJkSI5Ewc1jUd7TiUifj9p6CYzIuHtnPORUUE67vt7eiKjpdNdNaUIvXzSoAcx-B5FgYynKslZm5S6WwqQMEb6jFMeg1iN3DphDPbjUMCP2qZevm6fNTT0b7PzxE0POepqqEnyjIS1YOnMnyHkgSAQCtYMAwWATalS4tMFNRb-hbE2MGi-U1j3Z1Mq79x9Uce8ZXjD2a_sCE9x0fqTixO-pRUrQNrIqiX_bZlw96xktnUQy2wCoJiZRxKjZyRhPLxOQPR7FUyd8yFXjCHR_yf5mwYw",
    "expires_in": 43199,
    "scope": "all",
    "userName": "admin",
    "jti": "833ecd7d-8f37-4019-8ad0-0e827e383e9c"
}
```

将返回的 token 复制到 [https://jwt.io/](https://jwt.io/) 解析，发现已正确解析。

![JWT解析](https://public-image-lwh.oss-cn-shenzhen.aliyuncs.com/spring-security-oauth2.0/jwt-token-parse-test.png)

#### 校验 token

1. 使用 **Postman** 访问 `/oauth/check_token` 端点，我们试着添加错误的 `token` ，然后发送请求校验，发现返回错误；

![校验错误](https://public-image-lwh.oss-cn-shenzhen.aliyuncs.com/spring-security-oauth2.0/check-token-fail.png)

2. 使用 **Postman** 访问 `/oauth/check_token` 端点，我们使用正确的 `token` 校验，成功返回信息；

![校验成功](https://public-image-lwh.oss-cn-shenzhen.aliyuncs.com/spring-security-oauth2.0/check-token-success.png)

#### 刷新 token

使用 **Postman** 访问 `/oauth/token` 端点，其中参数 `grant_type` 使用 `refresh_token`，`refresh_token` 内容为我们从 `/oauth/token` 获取的 `refresh_token`（**注意不是 `access_token`**）；其他参数请自行配置，可参考如下：

![刷新token成功](https://public-image-lwh.oss-cn-shenzhen.aliyuncs.com/spring-security-oauth2.0/refresh-token-success.png)

## 搭建资源服务

1. 新建 `module` ，在 `pom.xml` 中添加依赖:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-oauth2</artifactId>
</dependency>
```

2. 在 `application.yml` 中添加 token 校验的相关参数，**将 token 校验地址改为认证服务的 token 校验地址**：

```yml
oauth2:
  resource-id: resource-server
  # token 校验地址
  check-token-url: http://127.0.0.1:8089/oauth/check_token
  client-id: oauth-server
  client-secret: 123456
```

### 配置资源服务

1. 新建 `ResourceServerConfig` 类，继承 `org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter`，添加注解 `@EnableResourceServer`，并配置 `token` 校验服务；

```java
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Value("${oauth2.check-token-url}")
    private String checkTokenUrl;

    @Value("${oauth2.resource-id}")
    private String resourceId;

    @Value("${oauth2.client-id}")
    private String clientId;

    @Value("${oauth2.client-secret}")
    private String clientSecret;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId(resourceId).stateless(true);
        resources.tokenServices(resourceServerTokenServices());
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .requestMatchers()
                .antMatchers("/users/**");
    }

    /**
     * 配置 token 校验服务
     * @return
     */
    @Bean
    ResourceServerTokenServices resourceServerTokenServices() {
        RemoteTokenServices remoteTokenServices = new RemoteTokenServices();
        remoteTokenServices.setCheckTokenEndpointUrl(checkTokenUrl);
        remoteTokenServices.setClientId(clientId);
        remoteTokenServices.setClientSecret(clientSecret);
        remoteTokenServices.setAccessTokenConverter(accessTokenConverter());
        return remoteTokenServices;
    }

    @Bean
    public AccessTokenConverter accessTokenConverter() {
        return new DefaultAccessTokenConverter();
    }
}
```

2. 添加 Controller

```java
@RestController
public class HomeController {

    @GetMapping("/users")
    public Map<String, Object> test(Authentication authentication) {
        Map<String, Object> data = new HashMap<>(1);
        data.put("user", authentication.getPrincipal());
        return data;
    }
}
```

### 测试

使用 **Postman** 访问 `/users` ，返回未授权错误：

![授权失败](https://public-image-lwh.oss-cn-shenzhen.aliyuncs.com/spring-security-oauth2.0/recource-test-fail.png)
 
使用 **Postman** 访问 `/users`，带上 `token` 访问，成功请求并获取到用户数据；

![授权成功](https://public-image-lwh.oss-cn-shenzhen.aliyuncs.com/spring-security-oauth2.0/recource-test-success.png)
 
 
参考：

1. [理解OAuth 2.0](http://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html)

2. [OAuth 2 Developers Guide](https://projects.spring.io/spring-security-oauth/docs/oauth2.html)

3. [Spring Security OAuth2自定义令牌配置](https://mrbird.cc/Spring-Security-OAuth2-Token-Config.html)