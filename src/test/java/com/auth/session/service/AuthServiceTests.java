package com.auth.session.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import com.auth.session.model.AuthRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.mockito.ArgumentCaptor;

class AuthServiceTests {
    private final AuthenticationManager manager = mock(AuthenticationManager.class);
    private final SecurityContextRepository contexts = mock(SecurityContextRepository.class);
    private final SessionAuthenticationStrategy sessions = mock(SessionAuthenticationStrategy.class);
    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final AuthService service = new AuthService(manager, contexts, sessions);

    @AfterEach
    void clearContext() { SecurityContextHolder.clearContext(); }

    @Test
    void successfulLoginPersistsAuthenticatedContextAfterSessionProtection() {
        Authentication authenticated = UsernamePasswordAuthenticationToken.authenticated("alice", null,
                java.util.List.of());
        when(manager.authenticate(any())).thenReturn(authenticated);
        assertSame(authenticated, service.signIn(new AuthRequest("alice", "secret"), request, response));
        ArgumentCaptor<SecurityContext> saved = ArgumentCaptor.forClass(SecurityContext.class);
        var order = inOrder(sessions, contexts);
        order.verify(sessions).onAuthentication(authenticated, request, response);
        order.verify(contexts).saveContext(saved.capture(), eq(request), eq(response));
        assertSame(authenticated, saved.getValue().getAuthentication());
    }

    @Test
    void loginRotatesSessionAndAuthenticationSurvivesNextRequest() {
        var repository = new org.springframework.security.web.context.HttpSessionSecurityContextRepository();
        var strategy = new org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy();
        var realService = new AuthService(manager, repository, strategy);
        var login = new org.springframework.mock.web.MockHttpServletRequest();
        var output = new org.springframework.mock.web.MockHttpServletResponse();
        String originalId = login.getSession().getId();
        Authentication authenticated = UsernamePasswordAuthenticationToken.authenticated(
                "alice", null, java.util.List.of());
        when(manager.authenticate(any())).thenReturn(authenticated);
        realService.signIn(new AuthRequest("alice", "secret"), login, output);
        assertNotEquals(originalId, login.getSession().getId());
        SecurityContextHolder.clearContext();
        var nextRequest = new org.springframework.mock.web.MockHttpServletRequest();
        nextRequest.setSession((org.springframework.mock.web.MockHttpSession) login.getSession());
        assertSame(authenticated, repository.loadDeferredContext(nextRequest).get().getAuthentication());
    }

    @Test
    void invalidCredentialsDoNotPersistAuthentication() {
        when(manager.authenticate(any())).thenThrow(new BadCredentialsException("Invalid credentials"));
        assertThrows(BadCredentialsException.class,
                () -> service.signIn(new AuthRequest("alice", "wrong"), request, response));
        verifyNoInteractions(sessions, contexts);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
}
