package com.ecom.config;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ecom.model.UserDtls;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Component
public class SecurityContextFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
    	/*HttpHeaders headers = response.getHeaders();
        if (headers != null) {
            String sessionId = headers.getFirst("sessionId");
            if("SESSIONID".equalsIgnoreCase(sessionId)) {
            	Authentication authentication = getAuthenticationFromSession(sessionId);
                if (authentication != null) {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } */
        
        /*if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("sessionId".equals(cookie.getName())) {
                	Authentication authentication = getAuthenticationFromSession(cookie.getName());
                	
                    if (authentication != null) {
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }
        }
        
    	List<String> cookies = response.getHeaders(HttpHeaders.SET_COOKIE).stream().toList();
        if (cookies != null && !cookies.isEmpty()) {
            String sessionId = cookies.get(0).substring(10, 46); // Fetch the first cookie
            if("SESSIONID".equalsIgnoreCase(sessionId)) {
            	Authentication authentication = getAuthenticationFromSession(sessionId);
                if (authentication != null) {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }*/
    	//String sessionId = request.getParameter("sessionId");
    	HttpSession session = request.getSession(false);
    	if(session != null) {
    		String sessionId = (String) session.getAttribute("sessionId");
    		if (sessionId != null) {
                System.out.println("Session ID in SecurityContextFilter: " + sessionId);
                Authentication authentication = getAuthenticationFromSession(sessionId);
                if (authentication != null) {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
                // Use sessionId for further processing
            }
    	}
        
        
        filterChain.doFilter(request, response);
    }
    

    private Authentication getAuthenticationFromSession(String sessionId) {
        RestTemplate restTemplate = new RestTemplate();
        String validateUrl =  "http://localhost:8093/signin/validate-session/" + sessionId;

        try {
            ResponseEntity<UserDtls> response =
                    restTemplate.getForEntity(validateUrl, UserDtls.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            	UserDtls userDetails = response.getBody();
                List<SimpleGrantedAuthority> authorities =  Arrays.asList(userDetails.getRole()).stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList();

                return new UsernamePasswordAuthenticationToken(userDetails.getName(), null, authorities);
            }
        } catch (Exception e) {
            System.out.println("Error fetching user details: " + e.getMessage());
        }
        return null;
    }
}
