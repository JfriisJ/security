package dk.friisjakobsen.security.controllers;

import dk.friisjakobsen.security.payload.request.LoginRequest;
import dk.friisjakobsen.security.payload.request.SignupRequest;
import dk.friisjakobsen.security.security.service.AuthenticationService;
import dk.friisjakobsen.security.security.service.UserDetailsImpl;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AuthApiController {

    @Autowired
    private AuthenticationService authenticationService; // This is your common service handling the logic

    @Operation(summary = "Authenticate user", description = "Authenticate user")
    @PostMapping("/login")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> authenticateUser(@Valid LoginRequest loginRequest) {
        return authenticationService.authenticateUser(loginRequest);
    }

    @Operation(summary = "Signup page", description = "Signup page")
    @PreAuthorize("permitAll()")
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        return authenticationService.registerUser(signUpRequest);
    }

    @Operation(summary = "Logout user", description = "Logout user")
    @PostMapping("logout")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<?> logoutUser(HttpServletRequest request, HttpServletResponse response) {
        return authenticationService.logoutUser(request, response);
    }

    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<?> profile(@AuthenticationPrincipal UserDetailsImpl userDetails
    ) {
        return authenticationService.getUserInformation(userDetails);
    }
    // Add other API endpoints here
}