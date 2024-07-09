package dk.friisjakobsen.security.controllers;

import dk.friisjakobsen.security.models.Role;
import dk.friisjakobsen.security.models.User;
import dk.friisjakobsen.security.payload.request.LoginRequest;
import dk.friisjakobsen.security.payload.request.SignupRequest;
import dk.friisjakobsen.security.payload.response.MessageResponse;
import dk.friisjakobsen.security.payload.response.UserInfoResponse;
import dk.friisjakobsen.security.repository.RoleRepository;
import dk.friisjakobsen.security.repository.UserRepository;
import dk.friisjakobsen.security.security.jwt.JwtUtils;
import dk.friisjakobsen.security.security.service.UserDetailsImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

//@CrossOrigin(origins = "*", maxAge = 3600)
@Controller
//@RequestMapping("/")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;

	Logger logger = LoggerFactory.getLogger(AuthController.class);

	@GetMapping("/login")
	@PreAuthorize("permitAll()")
	public String login(Model model, @AuthenticationPrincipal UserDetails userDetails) {
		addAuthenticationDetails(model, userDetails);
		model.addAttribute("loginRequest", new LoginRequest()); // Ensure loginRequest is added to the model
		return "security/login";
	}

	@PostMapping("/login")
	@PreAuthorize("permitAll()")
	public ResponseEntity<?> authenticateUser(@ModelAttribute("loginRequest") LoginRequest loginRequest) {

		logger.info("Login request: " + loginRequest.getUsername() + " " + loginRequest.getPassword());

		Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

		ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

		List<String> roles = userDetails.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList());

		return ResponseEntity.ok()
				.header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtUtils.generateTokenFromUsername(userDetails.getUsername()))
				.header(HttpHeaders.LOCATION, "/") // Redirect to the home page
				.body(new UserInfoResponse(userDetails.getId(),
						userDetails.getUsername(),
						userDetails.getEmail(),
						roles));
	}

	@GetMapping("/signup")
	public String signup(Model model, @AuthenticationPrincipal UserDetails userDetails) {
		addAuthenticationDetails(model, userDetails);
		return "security/signup";
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		logger.info("Signup request: " + signUpRequest.getUsername() + " " + signUpRequest.getEmail() + " " + signUpRequest.getRole());
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(),
				signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		// Existing role assignment code...

		user.setRoles(roles);
		userRepository.save(user);

		// Authenticate the new user
		UserDetailsImpl userDetails = authentication(signUpRequest.getUsername(), signUpRequest.getPassword());

		ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

		List<String> userRoles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());

		// Create a response object that includes the redirect URL
		Map<String, Object> response = new HashMap<>();
		response.put("redirectUrl", "/"); // The URL to redirect to
		response.put("userInfo", new UserInfoResponse(userDetails.getId(),
				userDetails.getUsername(),
				userDetails.getEmail(),
				userRoles));

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
				.body(response);
	}

	private UserDetailsImpl authentication(String username, String password){
		Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(username, password));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

		return userDetails;
	}
	@PostMapping("/logout")
	@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
	public ResponseEntity<?> logoutUser(HttpServletRequest request, HttpServletResponse response) {
		logger.info("Signing out user...");
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth != null) {
			new SecurityContextLogoutHandler().logout(request, response, auth);
		}
		SecurityContextHolder.getContext().setAuthentication(null);
		return ResponseEntity.ok().body(new MessageResponse("You've been signed out!"));
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
