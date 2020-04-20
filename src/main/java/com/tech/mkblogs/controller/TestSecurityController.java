package com.tech.mkblogs.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestSecurityController {

	
	@GetMapping("/")
    public String welcome() throws Exception {
        return "welcome";
    }
	
	@GetMapping("/user")
    public String user() throws Exception {
        return "User Welcome Here";
    }
	
	@GetMapping("/admin")
    public String admin() throws Exception {
        return "Admin Welcome Here";
    }
}
