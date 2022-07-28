package id.codecorn.autorizationserver.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import id.codecorn.autorizationserver.entity.Authorization;

@Repository
public interface AuthorizationDao extends JpaRepository<Authorization, String> {
}
