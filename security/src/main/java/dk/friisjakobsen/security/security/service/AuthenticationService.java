package dk.friisjakobsen.security.security.service;

import dk.friisjakobsen.security.models.ERole;
import dk.friisjakobsen.security.models.Role;
import dk.friisjakobsen.security.models.User;
import dk.friisjakobsen.security.payload.request.LoginRequest;
import dk.friisjakobsen.security.payload.request.SignupRequest;
import dk.friisjakobsen.security.payload.response.MessageResponse;
import dk.friisjakobsen.security.payload.response.UserInfoResponse;
import dk.friisjakobsen.security.repository.RoleRepository;
import dk.friisjakobsen.security.repository.UserRepository;
import dk.friisjakobsen.security.security.jwt.JwtUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Service class for handling authentication and authorization logic
 */
@Service
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final PasswordEncoder encoder;

    private final JwtUtils jwtUtils;

    Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    public AuthenticationService(AuthenticationManager authenticationManager, UserRepository userRepository, JwtUtils jwtUtils, RoleRepository roleRepository, PasswordEncoder encoder) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
    }

    /**
     * Authenticates a user
     *
     * @param loginRequest the login request
     * @return a response entity with a message
     */
    public ResponseEntity<?> authenticateUser(LoginRequest loginRequest) {

        logger.info("Login request: {}", loginRequest.getUsername());

        try {
            UserDetailsImpl userDetails = authentication(loginRequest.getUsername(), loginRequest.getPassword());

            if (userDetails == null) {
                logger.error("Invalid credentials");
                return ResponseEntity.badRequest().body(new MessageResponse("Error: Invalid credentials!"));
            }

            ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

            logger.info("User authenticated: {}", userDetails.getUsername());

            // Create a response object that includes the redirect URL

            return ResponseEntity
                    .ok()
                    .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                    .body(getUserInformation(userDetails));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Error: Unauthorized"));
        }
    }

    /**
     * Registers a new user
     *
     * @param signUpRequest the signup request
     * @return a response entity with a message
     */
    public ResponseEntity<?> registerUser(SignupRequest signUpRequest) {
        logger.info("Signup request: {} {}", signUpRequest.getUsername(), signUpRequest.getEmail());

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword()));

        Set<Role> roles = new HashSet<>();
        Role userRole = roleRepository.findByName(ERole.USER).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        roles.add(userRole);

        user.setRoles(roles);
        userRepository.save(user);

        UserDetailsImpl userDetails = authentication(signUpRequest.getUsername(), signUpRequest.getPassword());

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

        // Create a response object that includes the redirect URL

        return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .header(HttpHeaders.LOCATION, "/") // Redirect to the home page
                .body(getUserInformation(userDetails));
    }


    /**
     * Logs out the user by clearing the authentication context and invalidating the session
     *
     * @param request  the HTTP request
     * @param response the HTTP response
     * @return a response entity with a message
     */
    public ResponseEntity<?> logoutUser(HttpServletRequest request, HttpServletResponse response) {
        logger.info("Signing out user...");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        SecurityContextHolder.getContext().setAuthentication(null);
        return ResponseEntity.ok().body(new MessageResponse("You've been signed out!"));
    }

    /**
     * Gets the user information
     *
     * @param userDetails the user details
     * @return a response entity with the user information
     */
    public ResponseEntity<?> getUserInformation(UserDetailsImpl userDetails) {
        Map<String, Object> response = new HashMap<>();
        response.put("userInfo",
                new UserInfoResponse(
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
        );
        response.put("bearerToken", jwtUtils.generateTokenFromUsername(userDetails.getUsername()));
        return ResponseEntity.ok().body(response);
    }

    /**
     * Adds authentication details to the model
     *
     * @param model       the model
     * @param userDetails the user details
     */
    public void addAuthenticationDetails(Model model, UserDetails userDetails) {
        if (userDetails != null) {
            model.addAttribute("isLoggedIn", true);
            model.addAttribute("username", userDetails.getUsername());
            model.addAttribute("roles", userDetails.getAuthorities());
        } else {
            model.addAttribute("isLoggedIn", false);
        }
    }

    /**
     * Authenticates the user
     *
     * @param username the username
     * @param password the password
     * @return the user details
     */
    private UserDetailsImpl authentication(String username, String password) {
        // Authenticate the user
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        return userDetails;
    }

}
