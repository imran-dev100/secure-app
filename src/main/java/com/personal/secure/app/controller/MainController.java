package com.personal.secure.app.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/secure")
@RestController
public class MainController {
	
	
	
	/**
	 * Fix: Missing Security Headers
	 * https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
	 */
	@GetMapping("api")
	public ResponseEntity<String> securityHeaders(){
		return ResponseEntity.ok("Security headers added successfully");
	}
	

}
