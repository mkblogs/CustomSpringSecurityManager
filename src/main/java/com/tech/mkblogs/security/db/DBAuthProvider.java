package com.tech.mkblogs.security.db;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.tech.mkblogs.security.config.AccountAuthConfig;
import com.tech.mkblogs.security.db.model.Authorities;
import com.tech.mkblogs.security.db.model.User;

@Component
public class DBAuthProvider implements AuthenticationProvider{

	@Autowired
	AccountUserRepository repository;
	
	@Autowired
	AccountAuthConfig config;
	
	@Override
	@Transactional
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getPrincipal() + "";
	    String password = authentication.getCredentials() + "";
	    
	    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
	    User user = repository.findByLoginName(username);
	    if (user == null) {
	        throw new BadCredentialsException("1000");
	    }
	    if(config.getEncyprted()) {
	    	if (!encoder.matches(password, user.getPassword())) {
	 	        throw new BadCredentialsException("1000");
	 	    }
	    }else {
	    	if(!password.equalsIgnoreCase(user.getPassword())) {
	    		throw new BadCredentialsException("1000");
	    	}
	    }
	    if (user.getEnabled()) {
	        throw new DisabledException("1001");
	    }
	    List<Authorities> userRights = user.getAuthorities();
	    return new UsernamePasswordAuthenticationToken(username, null, userRights.stream().map(x -> new SimpleGrantedAuthority(x.getAuthority())).collect(Collectors.toList()));
	}
	
	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}
}
