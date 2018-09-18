package com.config.SpringBootSecurity.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
/*
This class will intercept POST requests on the /login path and attempt to authenticate the user.
When the user is successfully authenticated, it will return a JWT in the Authorization header of the response
reference : WebSecurityConfig.java
*/
public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter { // This filter will intercept a request and attempt to perform authentication from that request if the request matches the setRequiresAuthenticationRequestMatcher(RequestMatcher).

    static Logger LOG = LoggerFactory.getLogger("JWTLoginFilter");

    public JWTLoginFilter(String url, AuthenticationManager authManager) {

        super(new AntPathRequestMatcher(url));
        setAuthenticationManager(authManager);
        LOG.info("constructor called");
    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException, IOException, ServletException {
        LOG.info("Entry attemptAuthentication");
        AccountCredentials creds = new ObjectMapper()
                .readValue(req.getInputStream(), AccountCredentials.class);
        return getAuthenticationManager().authenticate(
                new UsernamePasswordAuthenticationToken(
                        creds.getUsername(),
                        creds.getPassword(),
                        Collections.emptyList()
                )
        );
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest req,
            HttpServletResponse res, FilterChain chain,
            Authentication auth) throws IOException, ServletException {
        LOG.info("Entry successfulAuthentication");
        TokenAuthenticationService
                .addAuthentication(res, auth.getName());
    }

}
