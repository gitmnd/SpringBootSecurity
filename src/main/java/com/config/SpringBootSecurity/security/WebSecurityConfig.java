package com.config.SpringBootSecurity.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/*
* we want to avoid exposing /users to everyone, so we will create a configuration that restricts its access
* */

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    static Logger LOG = LoggerFactory.getLogger("WebSecurityConfig");

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        LOG.info("Entry configure");
        http.csrf().disable().authorizeRequests()

                //Here we have decided that everyone can access the / route
                //the /login route is only publicly available for POST requests
                //For all other routes, authentication is required.
                //goal is to filter for the /login route, and every other route, to decide what should happen when someone access these routes.

                .antMatchers("/").permitAll()
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                .anyRequest().authenticated()
                .and()
                // We filter the api/login requests
                .addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                // And filter other requests to check the presence of JWT in header
                .addFilterBefore(new JWTAuthenticationFilter(),
                        UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        LOG.info("Entry configure with auth arg");
        // Create a default account
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{noop}password")
                .roles("ADMIN");
    }

    //Note : For astute readers, it might be obvious that you can also migrate plain text passwords by prefixing them with {noop}.
    //docs : Password Storage Format
    //The general format for a password is:
    // {id}encodedPassword
    //
    //Such that "id" is an identifier used to look up which PasswordEncoder should be used and "encodedPassword" is the original encoded password for the selected PasswordEncoder. The "id" must be at the beginning of the password, start with "{" and end with "}". If the "id" cannot be found, the "id" will be null.
}
