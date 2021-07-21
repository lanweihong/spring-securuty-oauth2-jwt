package com.lanweihong.security.auth.config;

import com.lanweihong.security.auth.dto.UserDTO;
import com.lanweihong.security.auth.service.impl.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 认证服务配置
 * @author lanweihong
 * @date 2021/1/13 01:30
 */
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    @Value("${jwt.key.path}")
    private String keyPairPath;

    @Value("${jwt.key.alias}")
    private String keyPairAlias;

    @Value("${jwt.key.storepass}")
    private String keyPairStorePassword;

    @Value("${jwt.key.password}")
    private String keyPairPassword;

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
        // 使用自定义的 ClientDetails ，添加缓存支持
        CustomClientDetailsService clientDetailsService = new CustomClientDetailsService(dataSource);
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
        // 从 classpath 目录下的证书 jwt.jks 中获取秘钥对
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource(keyPairPath), keyPairStorePassword.toCharArray());
        return keyStoreKeyFactory.getKeyPair(keyPairAlias, keyPairPassword.toCharArray());
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
