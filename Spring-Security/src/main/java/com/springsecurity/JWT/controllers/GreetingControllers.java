package com.springsecurity.JWT.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingControllers {

	@GetMapping
	public String sayHello() {
		return "Hello,Spring-Security";
	}
}
