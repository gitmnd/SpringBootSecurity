package com.config.SpringBootSecurity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.Date;

public class TokenAuthenticationService {

    static final long EXPIRATIONTIME = 864_000_000 ; //10 days
    static final String SECRET = "ThisIsASecret";
    static final String TOKEN_PREFIX = "Bearer";
    static final String HEADER_STRING = "Authorization";
    static Logger LOG = LoggerFactory.getLogger("TokenAuthenticationService");

    /*create a token based on a username and an expiration time, and then sign it with a secret (using an HMAC).*/
    static void addAuthentication(HttpServletResponse res, String username){
        LOG.info("Entry addAuthentication");
        String JWT =  Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
                .signWith(SignatureAlgorithm.HS512,SECRET)
                .compact();
        res.addHeader(HEADER_STRING, TOKEN_PREFIX + " " +JWT);
    }


    static Authentication getAuthentication(HttpServletRequest request){
        LOG.info("Entry getAuthentication");
        String token = request.getHeader(HEADER_STRING);
        if(token != null) {
            String user = Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token.replace(TOKEN_PREFIX,""))
                    .getBody()
                    .getSubject();
            return user !=null ? new UsernamePasswordAuthenticationToken(user,null, Collections.emptyList()):
            null;
        }
        return null;
    }
}
