package dk.friisjakobsen.security.controllers;

import dk.friisjakobsen.security.security.service.UserDetailsImpl;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/user")
public class ThymeleafController {


    @GetMapping("/admin/index")
    public String adminZone(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        addAuthenticationDetails(model, userDetails);
        return "admin/index";
    }

    @GetMapping("/user/index")
    public String userZone(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        addAuthenticationDetails(model, userDetails);
        return "user/index";
    }

    @GetMapping("/shared/index")
    public String sharedZone(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        addAuthenticationDetails(model, userDetails);
        return "shared/index";
    }

    @GetMapping("/simulateError")
    public String simulateError() {
        throw new Error("Simulated error");
//		throw new RuntimeException("Simulated error");
    }

    private void addAuthenticationDetails(Model model, UserDetails userDetails) {
        if (userDetails != null) {
            model.addAttribute("isLoggedIn", true);
            model.addAttribute("username", userDetails.getUsername());
            model.addAttribute("roles", userDetails.getAuthorities());
        } else {
            model.addAttribute("isLoggedIn", false);
        }
    }
}
