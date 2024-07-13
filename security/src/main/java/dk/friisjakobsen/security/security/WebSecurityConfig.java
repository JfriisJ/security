package dk.friisjakobsen.security.security;

import dk.friisjakobsen.security.security.jwt.AuthEntryPointJwt;
import dk.friisjakobsen.security.security.jwt.AuthTokenFilter;
import dk.friisjakobsen.security.security.service.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {
    private final UserDetailsServiceImpl userDetailsService;

    private final AuthEntryPointJwt unauthorizedHandler;

    private final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

    public WebSecurityConfig(UserDetailsServiceImpl userDetailsService, AuthEntryPointJwt unauthorizedHandler) {
        this.userDetailsService = userDetailsService;
        this.unauthorizedHandler = unauthorizedHandler;
    }

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(unauthorizedHandler)
                        .accessDeniedPage("/403.html"))
//				.sessionManagement(sessionManagement -> sessionManagement
//						.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
//						.requestMatchers(
//								new AntPathRequestMatcher("/", "GET"),
//								new AntPathRequestMatcher("/index", "GET"),
//								new AntPathRequestMatcher("/css/*", "GET"),
//								new AntPathRequestMatcher("/js/*", "GET"),
//								new AntPathRequestMatcher("/api/**", "GET"),
//								new AntPathRequestMatcher("/login", "POST"),
//								new AntPathRequestMatcher("/signup", "POST")
//						).permitAll()
                        .requestMatchers(
                                new AntPathRequestMatcher("/css/styles.css"),
                                new AntPathRequestMatcher("/js/scripts.js"),
                                new AntPathRequestMatcher("/images/**"),
                                new AntPathRequestMatcher("/favicon.ico"),
                                new AntPathRequestMatcher("/error.html"),
                                new AntPathRequestMatcher("/403.html"),
                                new AntPathRequestMatcher("/admin.html"),
                                new AntPathRequestMatcher("/shared/index.html"),
                                new AntPathRequestMatcher("/user/index.html"),
                                new AntPathRequestMatcher("/admin/index.html")
                        ).permitAll()
                        .requestMatchers("/").permitAll()
                        .requestMatchers("/profile").permitAll()
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/signup").permitAll()

//						.requestMatchers("/admin/**").hasRole("ADMIN")
//						.requestMatchers("/user/**").hasRole("USER")
//						.requestMatchers("/shared/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/simulateError").permitAll()
                        .requestMatchers("/admin").permitAll()
                        .requestMatchers("/user").permitAll()
                        .requestMatchers("/shared").permitAll()
                        .anyRequest().authenticated())
                .formLogin(formLogin -> formLogin
                        .loginPage("/login")
                        .defaultSuccessUrl("/", true)
                        .failureUrl("/error.html")
                        .permitAll())
                .formLogin(formLogin -> formLogin
                        .loginPage("/signup")
                        .defaultSuccessUrl("/", true)
                        .failureUrl("/error.html")
                        .permitAll())
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/")
                        .permitAll())
                .addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
