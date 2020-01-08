package ua.com.epam.configs;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class Security extends WebSecurityConfigurerAdapter{

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.inMemoryAuthentication().withUser("defaultUser").password("{noop}defaultPassword").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()
                .authorizeRequests()
                .anyRequest().authenticated()
                //.antMatchers("/api/library/").permitAll()
                .antMatchers(HttpMethod.POST, "/api/library/login").permitAll()
                .and()
                .addFilterBefore(new RequestProcessingJWTFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new LoginFilter("/api/library/login", authenticationManager()), UsernamePasswordAuthenticationFilter.class)
        ;


    }


}