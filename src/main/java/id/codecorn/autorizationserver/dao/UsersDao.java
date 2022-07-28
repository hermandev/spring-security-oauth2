package id.codecorn.autorizationserver.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import id.codecorn.autorizationserver.entity.Users;

@Repository
public interface UsersDao extends JpaRepository<Users, String> {
    Users findByUsername(String username);
}
