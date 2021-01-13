package com.lanweihong.security.auth.service.impl;

import com.lanweihong.security.auth.dto.UserDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * @author lanweihong
 * @date 2021/1/13 01:39
 */
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
