package com.example.securityjwt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class TestController {

    @GetMapping("/")
    public String home() {
        return "home page";
    }

    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public String profile(Authentication authentication) {
        log.info("Username={}, roles={}", authentication.getPrincipal(), authentication.getAuthorities());
        return "profile page";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String admin() {
        return "admin page";
    }
}
