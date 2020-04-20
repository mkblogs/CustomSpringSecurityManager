package com.tech.mkblogs.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.tech.mkblogs.security.config.AccountAuthConfig;
import com.tech.mkblogs.security.db.DBAuthProvider;
import com.tech.mkblogs.security.inmemory.InMemoryAuthProvider;

@Component
public class AccountAuthenticateManager implements AuthenticationManager{

	
	private AuthenticationProvider provider;
	
	@Autowired
	private AccountAuthConfig authConfig;
	
	@Autowired
	ApplicationContext context;
	
	public AccountAuthenticateManager() {		
	}
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String authType = authConfig.getAuthType();
		switch (authType.toLowerCase()) {
		case "inmemory":
				provider = context.getBean(InMemoryAuthProvider.class);
			break;
		case "db":
			provider = context.getBean(DBAuthProvider.class);
		break;	
		case "ldap":
			provider = context.getBean(DBAuthProvider.class);
		break;		
		default:
			provider = context.getBean(InMemoryAuthProvider.class);
			break;
		}
		return provider.authenticate(authentication);
	}
	
}
