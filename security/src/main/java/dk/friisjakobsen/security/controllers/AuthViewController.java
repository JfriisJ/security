package dk.friisjakobsen.security.controllers;

import dk.friisjakobsen.security.models.ERole;
import dk.friisjakobsen.security.payload.request.LoginRequest;
import dk.friisjakobsen.security.security.service.AuthenticationService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Arrays;
import java.util.Objects;

@CrossOrigin(origins = "http://localhost:8080", maxAge = 3600, allowCredentials = "true")
@Tag(name = "Authentication", description = "Authentication and Authorization API")
@Controller
@RequestMapping("/")
public class AuthViewController {


    private final AuthenticationService authenticationService; // Use the same service for common logic

    public AuthViewController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @GetMapping("/")
    public String homePage(Model model, @AuthenticationPrincipal HttpServletRequest userDetails) {

        System.out.println(Arrays.toString(new boolean[]{userDetails.isUserInRole("ADMIN")}));
        return "index";
    }

    @GetMapping("/login")
    public String loginPage() {
        return "security/login";
    }

    @PostMapping("/login")
    public String authenticateUser(HttpServletRequest request, Model model) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername(username);
        loginRequest.setPassword(password);

        // Assuming authenticateUser in AuthenticationService returns a ResponseEntity
        // You might need to adjust this based on your actual return type and logic
        ResponseEntity<?> response = authenticationService.authenticateUser(loginRequest);

        // Based on the response, redirect or show an error
        // This is a simplistic approach, adjust according to your needs
        if (response.getStatusCode() == HttpStatus.OK) {
            return "redirect:/"; // Redirect to home or another appropriate page
        } else {
            model.addAttribute("error", "Invalid username or password");
            return "security/login"; // Stay on the login page and display an error
        }
    }

    @GetMapping("/signup")
    public String signupPage() {
        return "security/signup";
    }

    @GetMapping("admin/index")
    public String adminZone(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        authenticationService.addAuthenticationDetails(model, userDetails);
        return "admin/index";
    }

    @GetMapping("user/index")
    public String userZone(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        authenticationService.addAuthenticationDetails(model, userDetails);
        return "user/index";
    }

    @GetMapping("shared/index")
    public String sharedZone(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        authenticationService.addAuthenticationDetails(model, userDetails);
        return "shared/index";
    }

    @GetMapping("/simulateError")
    public String simulateError() {
        throw new RuntimeException("Simulated error");
    }

    // Add other view endpoints here
}