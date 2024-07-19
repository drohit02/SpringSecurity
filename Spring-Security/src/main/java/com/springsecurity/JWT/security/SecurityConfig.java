package com.springsecurity.JWT.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
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
    
    
    @Bean
    UserDetailsService userDetailsService() {
    	UserDetails user1 = User.withUsername("user1")
    							.password("{noop}pass123")
    							.roles("USER")
    							.build();
    	
    	UserDetails admin = User.withUsername("admin")
    							.password("{noop}admin123")
    							.roles("ADMIN")
    							.build();
    	
    	return new InMemoryUserDetailsManager(user1,admin);
    }

}
