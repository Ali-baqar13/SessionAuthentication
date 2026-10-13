package com.auth.session.controller;

import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.session.model.AuthRequest;
import com.auth.session.service.AuthService;


@RestController
@RequestMapping("/auth")
public class AuthController {


    private final AuthService authService;

    public AuthController(AuthService authService) { this.authService = authService; }

    @GetMapping("/csrf")
    public CsrfResponse csrf(CsrfToken token) {
        return new CsrfResponse(token.getHeaderName(), token.getToken());
    }

    @PostMapping({"", "/login"})
    public ResponseEntity<?> authenticate(@RequestBody AuthRequest req,
            HttpServletRequest request, HttpServletResponse response) {
        if (req.getUsername() == null || req.getUsername().isBlank()
                || req.getPassword() == null || req.getPassword().isBlank()) {
            return ResponseEntity.badRequest().body("Username and password are required");
        }
        try {
            return ResponseEntity.ok(user(authService.signIn(req, request, response)));
        } catch (AuthenticationException exception) {
            return ResponseEntity.status(401).body("Invalid username or password");
        }
    }

    @GetMapping("/me")
    public UserResponse me(Authentication authentication) { return user(authentication); }

    private UserResponse user(Authentication authentication) {
        return new UserResponse(authentication.getName(), authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList());
    }

    public record UserResponse(String username, List<String> authorities) {}
    public record CsrfResponse(String headerName, String token) {}
    
}
