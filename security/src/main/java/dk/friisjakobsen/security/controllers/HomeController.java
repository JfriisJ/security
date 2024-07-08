package dk.friisjakobsen.security.controllers;

import dk.friisjakobsen.security.security.service.UserDetailsImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

	@GetMapping("/")
	public String index(Model model) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		boolean isLoggedIn = authentication != null && authentication.isAuthenticated() && !(authentication.getPrincipal() instanceof String);
		model.addAttribute("isLoggedIn", isLoggedIn);
		return "index"; // Ensure this maps to src/main/resources/templates/index.html
	}

	@GetMapping("/login")
	public String loginPage() {
		return "login";
	}

	@GetMapping("/signup")
	public String signupPage() {
		return "signup";
	}

	@GetMapping("/about")
	public String aboutPage(Model model) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		boolean isLoggedIn = authentication != null && authentication.isAuthenticated() && !(authentication.getPrincipal() instanceof String);
		model.addAttribute("isLoggedIn", isLoggedIn);
		return "about";
	}

	@GetMapping("/contact")
	public String contactPage(Model model) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		boolean isLoggedIn = authentication != null && authentication.isAuthenticated() && !(authentication.getPrincipal() instanceof String);
		model.addAttribute("isLoggedIn", isLoggedIn);
		return "contact";
	}

}