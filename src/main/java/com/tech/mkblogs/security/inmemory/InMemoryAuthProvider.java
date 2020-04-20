package com.tech.mkblogs.security.inmemory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import com.tech.mkblogs.security.config.AccountAuthConfig;

@Component
public class InMemoryAuthProvider implements AuthenticationProvider{

	@Autowired
	private AccountAuthConfig authConfig;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getPrincipal() + "";
	    String password = authentication.getCredentials() + "";
		if ("user".equalsIgnoreCase(username)) {
			return isValidInMemoryUser(username, password, authConfig.getEncyprted());
		}else {
			return isValidInMemoryAdmin(username, password, authConfig.getEncyprted());
		}
	}
	
	/**
	 * 
	 * @param username
	 * @param password
	 * @param encyprted
	 * @return
	 */
	protected UsernamePasswordAuthenticationToken isValidInMemoryUser(String username,String password,Boolean encyprted) {
		List<String> userRole = new ArrayList<String>();
		userRole.add("ROLE_USER");
		Collection<? extends GrantedAuthority> authorities 
				= userRole.stream().map(x -> new SimpleGrantedAuthority(x)).collect(Collectors.toList());
		
		if(encyprted) {
			BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
			String encodedPassword = encoder.encode(password);
			if ("user".equalsIgnoreCase(username) && encoder.matches("user@123",encodedPassword)){
		       return new UsernamePasswordAuthenticationToken
		              (username, null, authorities);
		    }else {
		       throw new BadCredentialsException("In-Memory Authentication Failed for given user:"+username + " and encyrted password");
		    }
		}else {
			if ("user".equalsIgnoreCase(username) && "user@123".equalsIgnoreCase(password)) {
		       return new UsernamePasswordAuthenticationToken
		              (username, null, authorities);
		    }else {
		    	throw new BadCredentialsException("In-Memory Authentication Failed for given user:"+username + " and given password");
		    }
		}
	}
	
	
	/**
	 * 
	 * @param username
	 * @param password
	 * @param encyprted
	 * @return
	 */
	protected UsernamePasswordAuthenticationToken isValidInMemoryAdmin(String username,String password,Boolean encyprted) {
		List<String> userRole = new ArrayList<String>();
		userRole.add("ROLE_ADMIN");
		Collection<? extends GrantedAuthority> authorities 
				= userRole.stream().map(x -> new SimpleGrantedAuthority(x)).collect(Collectors.toList());
		
		if(encyprted) {
			BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
			String encodedPassword = encoder.encode(password);
			if ("admin".equalsIgnoreCase(username) && encoder.matches("admin@123",encodedPassword)) {
		       return new UsernamePasswordAuthenticationToken
		              (username, null, authorities);
		    }else {
		    	throw new BadCredentialsException("In-Memory Authentication Failed for given user: "+username + " and encyrted password");
		    }
		}else {
			if ("admin".equalsIgnoreCase(username) && "admin@123".equalsIgnoreCase(password)){
		       return new UsernamePasswordAuthenticationToken
		              (username, null, authorities);
		    }else {
		    	throw new BadCredentialsException("In-Memory Authentication Failed for given user:"+username + " and given password");
		    }
		}
	}

	
	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}
}
