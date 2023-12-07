package com.security.jwt.demo.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.security.jwt.demo.config.filters.FilterBasicAuth;
import com.security.jwt.demo.config.filters.FilterOncePerRequest;
import com.security.jwt.demo.config.filters.FilterUserPassAuth;
import org.springframework.context.annotation.Lazy;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private FilterOncePerRequest requestFilter;

    @Autowired
    @Lazy
    private AuthenticationManager authenticationManager;

    @Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests((authorize) -> authorize.requestMatchers("/**").authenticated())
            .addFilterBefore(requestFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilter(new FilterUserPassAuth(authenticationManager))
            .addFilter(new FilterBasicAuth(authenticationManager))
            .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200", "http://localhost:4200/"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * 
     * 1- Al implementar los filtros de autenticación, se deshabilita la autenticación por defecto de Spring Security.
     * 2- OncePerRequestFilter: Se ejecuta una vez por cada request. (Con permitAll o con authenticated)
     * 3- addFilter de custom UserPasswordAuthentionFilter: Se ejecuta con un POST /login y se ejecuta una vez.
     * 4- addFilter de custom BasicAuthentionFilter: Se ejecuta con una vez por cada request, pero no se ejecuta en POST /login.
     * 5- Si en cualquiera de los filtros que se ejecutan siempre agrego SecurityContextHolder.getContext().setAuthentication(authentication), entonces el request ya estaría autenticado.
     * 
     */


    /*
     Description: Security configuration to permit all request:
     @Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests((authorize) -> authorize.requestMatchers("/**").permitAll())
            .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
     */

     /* 
     Description: Security to authenticate with basic or form login:
     @Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests((authorize) -> authorize.requestMatchers("/**").authenticated())
            //.httpBasic(Customizer.withDefaults())// it works with basic
            .formLogin(Customizer.withDefaults())// POST /login 302 Found - Bad credentials if password is wrong
            .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }*/
    
}

