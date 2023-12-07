package com.security.jwt.demo.config.filters;

import java.io.IOException;
import java.util.ArrayList;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


public class FilterUserPassAuth extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;
    
	public FilterUserPassAuth(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        System.out.println("***** User Pass Auth Filter Attempt *****");
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user", 
                                        "password", new ArrayList<>()));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
    	System.out.println("***** User Pass Auth Filter Sucessful Auth *****");
        res.addHeader("Authorization", "Bearer XXXX");
    }

}
