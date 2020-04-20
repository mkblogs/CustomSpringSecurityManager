package com.tech.mkblogs.security.db.model;

import java.time.LocalDateTime;

import javax.persistence.EntityListeners;
import javax.persistence.MappedSuperclass;
import javax.persistence.Version;

import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

/**
 * All model classes are suppose to implement from this base model class.
 * @author 
 * @version 2.0
 * 
 */
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseModel {
	
	@CreatedDate
	protected LocalDateTime createdTs;
	
	@CreatedBy
	protected String createdBy;
	
	@LastModifiedDate
	protected LocalDateTime lastModifiedTs;
	
	@LastModifiedBy
	protected String lastModifiedBy;
	
	@Version
	protected Integer version;
	
}
