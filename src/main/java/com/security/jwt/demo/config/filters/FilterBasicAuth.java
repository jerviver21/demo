package com.security.jwt.demo.config.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class FilterBasicAuth extends BasicAuthenticationFilter {
	
	
    public FilterBasicAuth(AuthenticationManager authManager) {
        super(authManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        System.out.println("***** Basic Auth Filter *****");
        UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken("user", 
	                		null, 
	                		new ArrayList<>());
        SecurityContextHolder.getContext().setAuthentication(principal);
        chain.doFilter(req, res);
    }
    
}
