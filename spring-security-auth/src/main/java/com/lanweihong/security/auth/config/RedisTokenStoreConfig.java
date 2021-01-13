package com.lanweihong.security.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import javax.annotation.Resource;

/**
 * 配置 token 存储方式为 redis
 * @author lanweihong 986310747@qq.com
 * @date 2021/1/13 21:15
 */
@Configuration
public class RedisTokenStoreConfig {

    @Resource
    private RedisConnectionFactory connectionFactory;

    @Bean
    public TokenStore redisTokenStore() {
        return new RedisTokenStore(connectionFactory);
    }
}
