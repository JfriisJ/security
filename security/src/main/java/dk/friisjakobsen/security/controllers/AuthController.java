package dk.friisjakobsen.security.controllers;

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
import dk.friisjakobsen.security.security.service.UserDetailsImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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

@CrossOrigin(origins = "http://localhost:8080", maxAge = 3600, allowCredentials="true")
@Tag(name = "Authentication", description = "Authentication and Authorization API")
@Controller
@RequestMapping("/")
public class AuthController {

	private final AuthenticationManager authenticationManager;

	private final UserRepository userRepository;

	private final RoleRepository roleRepository;

	private final PasswordEncoder encoder;

	private final JwtUtils jwtUtils;

	Logger logger = LoggerFactory.getLogger(AuthController.class);

	public AuthController(AuthenticationManager authenticationManager, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder encoder, JwtUtils jwtUtils) {
		this.authenticationManager = authenticationManager;
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
		this.encoder = encoder;
		this.jwtUtils = jwtUtils;
	}

	@Operation(summary = "Login page", description = "Login page")
	@GetMapping("login")
	@PreAuthorize("permitAll()")
	public String login() {
		return "security/login";
	}

	@Operation(summary = "Authenticate user", description = "Authenticate user")
	@PostMapping("login")
	@PreAuthorize("permitAll()")
	public ResponseEntity<?> authenticateUser(@Valid LoginRequest loginRequest) {

		logger.info("Login request: " + loginRequest.getUsername() + " " + loginRequest.getPassword());

		Authentication authentication = authenticationManager
				.authenticate(
						new UsernamePasswordAuthenticationToken(
								loginRequest.getUsername(), loginRequest.getPassword()
						)
				);

		if (authentication == null) {
			logger.error("Invalid credentials");
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Invalid credentials!"));
		}

		SecurityContextHolder.getContext().setAuthentication(authentication);

		// Authenticate the user
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();


		ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

		logger.info("User authenticated: " + userDetails.getUsername());

		// Create a response object that includes the redirect URL
		Map<String, Object> response = getUserInformation(userDetails);

		return ResponseEntity
				.ok()
				.header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
				.header(HttpHeaders.LOCATION, "/") // Redirect to the home page
				.body(response);
	}

	@Operation(summary = "Signup page", description = "Signup page")
	@GetMapping("signup")
	@PreAuthorize("permitAll()")
	public String signup() {
		return "security/signup";
	}

	@Operation(summary = "Register user", description = "Register user")
	@PostMapping("signup")
	public ResponseEntity<?> registerUser(@Valid SignupRequest signUpRequest) {
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

		// Authenticate the user
		Authentication authentication = authenticationManager
				.authenticate(
						new UsernamePasswordAuthenticationToken(
								signUpRequest.getUsername(), signUpRequest.getPassword()
						)
				);
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

		ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

		// Create a response object that includes the redirect URL
		Map<String, Object> response = getUserInformation(userDetails);

		return ResponseEntity
				.ok()
				.header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
				.header(HttpHeaders.LOCATION, "/") // Redirect to the home page
				.body(response);

	}

	private Map<String, Object> getUserInformation(UserDetailsImpl userDetails) {
		Map<String, Object> response = new HashMap<>();
		response.put("userInfo",
				new UserInfoResponse(
						userDetails.getId(),
						userDetails.getUsername(),
						userDetails.getEmail(),
						userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
		);
		response.put("bearerToken", jwtUtils.generateTokenFromUsername(userDetails.getUsername()));
		return response;
	}

	@Operation(summary = "Logout user", description = "Logout user")
	@PostMapping("logout")
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

	@GetMapping("/profile")
	@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
	public String profile(
//			Model model, @AuthenticationPrincipal UserDetails userDetails
	) {
//		addAuthenticationDetails(model, userDetails);
//		User user = userRepository.findByUsername(userDetails.getUsername()).get();
//		model.addAttribute("email", user.getEmail());
//		model.addAttribute("roles", user.getRoles());
//		model.addAttribute("username", user.getUsername());
//		model.addAttribute("id", user.getId());
//
//		System.out.println("User: " + user.getUsername() + " " + user.getEmail() + " " + user.getRoles());
		return "shared/profile";
	}

	@Operation(summary = "Update profile", description = "Update profile")
	@PostMapping("profile/update")
	@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
	public ResponseEntity<?> updateProfile(@AuthenticationPrincipal UserDetails userDetails, @RequestBody SignupRequest signUpRequest) {
		logger.info("Updating profile for user: " + userDetails.getUsername());
		User user = userRepository.findByUsername(userDetails.getUsername()).get();
		user.setEmail(signUpRequest.getEmail());
		userRepository.save(user);
		return ResponseEntity.ok().body(new MessageResponse("Profile updated successfully!"));
	}

	@PostMapping("/update/{id}")
	public ResponseEntity<?> updateUser(@PathVariable("id") long id, @RequestBody User user) {
		logger.info("Updating user with id: " + id);
		Optional<User> userData = userRepository.findById(id);

		if (userData.isPresent()) {
			User _user = userData.get();
			_user.setUsername(user.getUsername());
			_user.setEmail(user.getEmail());
			_user.setPassword(user.getPassword());
			return new ResponseEntity<>(userRepository.save(_user), HttpStatus.OK);
		} else {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
	}

	@PostMapping("delete/{username}")
	public ResponseEntity<?> deleteUser(Model model, @PathVariable("username") String username) {
		logger.info("Deleting user with id: {}", username);
		String validUsername;
		if (username.isEmpty()) {
			validUsername = (model.getAttribute("username").toString());
		} else {
			validUsername = username;
		}

		User user = userRepository.findByUsername(validUsername).orElseThrow(() -> new RuntimeException("Error: User is not found."));

		Map<String, Object> response = new HashMap<>();
		response.put("message", "User with username: " + user.getUsername() + "deleted successfully!");

		userRepository.deleteById(user.getId());

		return ResponseEntity.ok().header(HttpHeaders.LOCATION, "/").body(response);
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


	private UserDetailsImpl authentication(String username, String password) {
		Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

		return userDetails;
	}



	@GetMapping("admin/index")
	public String adminZone(Model model, @AuthenticationPrincipal UserDetails userDetails) {
		addAuthenticationDetails(model, userDetails);
		return "admin/index";
	}

	@GetMapping("user/index")
	public String userZone(Model model, @AuthenticationPrincipal UserDetails userDetails) {
		addAuthenticationDetails(model, userDetails);
		return "user/index";
	}

	@GetMapping("shared/index")
	public String sharedZone(Model model, @AuthenticationPrincipal UserDetails userDetails) {
		addAuthenticationDetails(model, userDetails);
		return "shared/index";
	}

	@GetMapping("/simulateError")
	public String simulateError() {
		throw new RuntimeException("Simulated error");
	}

}
