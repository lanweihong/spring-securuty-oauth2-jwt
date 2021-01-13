package com.lanweihong.security.resource.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author lanweihong 986310747@qq.com
 * @date 2021/1/13 16:47
 */
@RestController
public class HomeController {

    @GetMapping("/users")
    public Map<String, Object> test(Authentication authentication) {
        Map<String, Object> data = new HashMap<>(1);
        data.put("user", authentication.getPrincipal());
        return data;
    }

}
