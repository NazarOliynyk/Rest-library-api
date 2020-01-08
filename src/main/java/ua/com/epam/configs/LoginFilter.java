package ua.com.epam.configs;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class LoginFilter extends AbstractAuthenticationProcessingFilter{

    LoginFilter(String url, AuthenticationManager authManager) {
        super(new AntPathRequestMatcher(url)); // defines the url this filter reacts on
        setAuthenticationManager(authManager);
    }

    @Override
    public Authentication attemptAuthentication
            (HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
            throws AuthenticationException, IOException, ServletException {

        ClientDataAuthModel creds = new ObjectMapper()
                .readValue(httpServletRequest.getInputStream(), ClientDataAuthModel.class);

        System.out.println(creds);

        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();
        authorityList.add(new SimpleGrantedAuthority("ROLE_USER"));
        return getAuthenticationManager().authenticate(
                new UsernamePasswordAuthenticationToken(
                        creds.getUsername(),
                        creds.getPassword(),
                        authorityList
                )
        );
    }

    @Override
    protected void successfulAuthentication
            (HttpServletRequest req,
             HttpServletResponse res,
             FilterChain chain,
             Authentication auth) throws IOException, ServletException {

        String jwtoken = Jwts.builder()
                .setSubject(auth.getName())
                .signWith(SignatureAlgorithm.HS512, "yes".getBytes())
                .setExpiration(new Date(System.currentTimeMillis()+900000))
                .compact();

        String fullHeaderValue = "Bearer "+jwtoken;
        res.addHeader("Authorization", fullHeaderValue);

    }
}