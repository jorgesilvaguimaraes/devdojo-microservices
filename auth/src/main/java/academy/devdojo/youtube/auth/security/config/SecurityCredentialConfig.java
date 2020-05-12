package academy.devdojo.youtube.auth.security.config;

import academy.devdojo.youtube.auth.security.config.filter.JwtUsernameAndPasswordAuthenticationFilter;
import academy.devdojo.youtube.core.property.JwtConfiguration;
import academy.devdojo.youtube.security.config.SecurityTokenConfig;
import academy.devdojo.youtube.security.token.creator.TokenCreator;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;

import javax.servlet.http.HttpServletResponse;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@EnableWebSecurity
public class SecurityCredentialConfig extends SecurityTokenConfig {

    private final UserDetailsService userDetailsService;
    private final TokenCreator tokenCreator;

    public SecurityCredentialConfig(JwtConfiguration jwtConfiguration, UserDetailsService userDetailsService1, TokenCreator tokenCreator) {
        super(jwtConfiguration);
        this.userDetailsService = userDetailsService1;
        this.tokenCreator = tokenCreator;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfiguration, tokenCreator ));
        super.configure(http);


    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
