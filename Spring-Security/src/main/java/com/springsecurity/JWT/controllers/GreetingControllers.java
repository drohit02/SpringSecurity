package com.springsecurity.JWT.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingControllers {

	@GetMapping
	public String sayHello() {
		return "Hello,Spring-Security";
	}
	
	@PreAuthorize("hasRole('USER')")
	@GetMapping("/user")
	public String sayHelloToUser() {
		return "Hello,User";
	}
	
	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/admin")
	public String sayHelloToAdminr() {
		return "Hello,Admin";
	}
	
}
