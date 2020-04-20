package com.tech.mkblogs.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity      
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    AccountAuthenticateManager manager;
   	
  // Securing the urls and allowing role-based access to these urls.
  @Override
  protected void configure(HttpSecurity http) throws Exception {
      http.authorizeRequests()
      .antMatchers("/admin").hasRole("ADMIN")
      .antMatchers("/user").hasAnyRole("USER","ADMIN")
      .antMatchers("/").permitAll()
      .and().csrf().disable();
      
      http.formLogin();
     // http.logout().invalidateHttpSession(true);
  }
	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		return manager;
	}
}
