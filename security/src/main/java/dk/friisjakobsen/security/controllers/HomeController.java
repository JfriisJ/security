package dk.friisjakobsen.security.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

	@GetMapping("/")
	public String index() {
		return "index";
	}
	@GetMapping("/login")
	public String loginPage() {
		return "login";
	}

	@GetMapping("/signup")
	public String signupPage() {
		return "signup";
	}

}