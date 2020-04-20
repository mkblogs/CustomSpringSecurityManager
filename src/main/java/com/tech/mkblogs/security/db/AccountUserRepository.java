package com.tech.mkblogs.security.db;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tech.mkblogs.security.db.model.User;

@Repository
public interface AccountUserRepository extends JpaRepository<User, Integer> {

	User findByLoginName(String loginName);
	
}
