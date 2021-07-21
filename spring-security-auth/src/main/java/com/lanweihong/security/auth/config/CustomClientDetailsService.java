package com.lanweihong.security.auth.config;

import com.lanweihong.security.auth.consts.CacheConstants;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;

import javax.sql.DataSource;

/**
 * 自定义的 ClientDetails ，基于 JDBC 存储模式，添加缓存支持，查询更快
 * @author lanweihong 986310747@qq.com
 * @date 2021/7/22 03:31
 */
public class CustomClientDetailsService extends JdbcClientDetailsService {

    public CustomClientDetailsService(DataSource dataSource) {
        super(dataSource);
    }

    @Cacheable(value = {CacheConstants.OAUTH_CLIENT_DETAILS_KEY}, key = "#clientId")
    @Override
    public ClientDetails loadClientByClientId(String clientId) throws InvalidClientException {
        return super.loadClientByClientId(clientId);
    }

    @CachePut(value = {CacheConstants.OAUTH_CLIENT_DETAILS_KEY}, key = "#clientDetails.clientId")
    @Override
    public void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException {
        super.addClientDetails(clientDetails);
    }

    @CachePut(value = {CacheConstants.OAUTH_CLIENT_DETAILS_KEY}, key = "#clientDetails.clientId")
    @Override
    public void updateClientDetails(ClientDetails clientDetails) throws NoSuchClientException {
        super.updateClientDetails(clientDetails);
    }

    @CachePut(value = {CacheConstants.OAUTH_CLIENT_DETAILS_KEY}, key = "#clientId")
    @Override
    public void updateClientSecret(String clientId, String secret) throws NoSuchClientException {
        super.updateClientSecret(clientId, secret);
    }

    @CacheEvict(value = {CacheConstants.OAUTH_CLIENT_DETAILS_KEY}, key = "#clientId")
    @Override
    public void removeClientDetails(String clientId) throws NoSuchClientException {
        super.removeClientDetails(clientId);
    }
}
