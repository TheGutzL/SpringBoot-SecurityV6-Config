package com.app.persistence.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.app.persistence.entity.RoleEntity;

@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
    
    List<RoleEntity> findRoleEntitiesByRoleEnumIn(List<String> roleNames);

}
