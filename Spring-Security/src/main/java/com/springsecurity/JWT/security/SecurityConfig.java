package com.springsecurity.JWT.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    	  /* authenticating every request */
         http.authorizeHttpRequests((request)->request.anyRequest().authenticated());
         
         /* Making every request stateless */
         http.sessionManagement((session)->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
         
         /* enable the Form-Based Authentication functionality using HTML Form for Login and Logout*/
         //http.formLogin(withDefaults());
         
         /* enable the Basic Authentication functionality using Browser Pop-Up*/
         http.httpBasic(withDefaults());
         return http.build();
    }

}
