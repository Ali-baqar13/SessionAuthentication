package com.auth.session.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import com.auth.session.model.AuthRequest;

@Service
public class AuthService {
    private final AuthenticationManager authManager;
    private final SecurityContextRepository contexts;
    private final SessionAuthenticationStrategy sessions;

    public AuthService(AuthenticationManager authManager, SecurityContextRepository contexts,
            SessionAuthenticationStrategy sessions) {
        this.authManager = authManager;
        this.contexts = contexts;
        this.sessions = sessions;
    }

    public Authentication signIn(AuthRequest req, HttpServletRequest request, HttpServletResponse response) {

        UsernamePasswordAuthenticationToken loginToken =
                new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword());
        Authentication authentication = authManager.authenticate(loginToken);
        sessions.onAuthentication(authentication, request, response);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        contexts.saveContext(context, request, response);
        return authentication;
    }
    
}
