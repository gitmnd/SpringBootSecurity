package com.config.SpringBootSecurity.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/*
* What this filter does is to intercept all requests to validate the presence of the JWT–that is, the ones that are not issued
* to / nor /users. This validation is done with the help of the TokenAuthenticationService class.
* */
public class JWTAuthenticationFilter extends GenericFilterBean {

    static Logger LOG = LoggerFactory.getLogger("WebSecurityConfig");

    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain filterChain)
            throws IOException, ServletException {
        LOG.info("doFilter is called");
        Authentication authentication = TokenAuthenticationService
                .getAuthentication((HttpServletRequest)request);

        SecurityContextHolder.getContext()
                .setAuthentication(authentication);
        filterChain.doFilter(request,response);
    }
}
