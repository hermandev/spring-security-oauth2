package id.codecorn.autorizationserver.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import id.codecorn.autorizationserver.entity.Client;

@Repository
public interface ClientDao extends JpaRepository<Client, String> {

}
