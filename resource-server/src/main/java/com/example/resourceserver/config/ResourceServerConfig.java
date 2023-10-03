package com.example.resourceserver.config;

import com.example.resourceserver.converter.JwtAuthenticationConverter;
import com.example.resourceserver.converter.JwtRoleConverter;
import com.example.resourceserver.filter.MyBasicAuthentificationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@EnableWebSecurity
public class ResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new JwtRoleConverter());

        http
                .authorizeRequests()
                .antMatchers("/resource/**")
                .access("hasAuthority('SCOPE_resource.read')")
                .antMatchers("/resource/**").hasRole("USER")
                .and()
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter);
        //http.addFilterBefore(new MyBasicAuthentificationFilter(), BasicAuthenticationFilter.class);
        return http.build();
    }

}