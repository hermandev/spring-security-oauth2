package id.codecorn.autorizationserver.service;

import id.codecorn.autorizationserver.entity.Roles;
import id.codecorn.autorizationserver.entity.Users;
import id.codecorn.autorizationserver.exception.UserIsRegisteredException;

public interface UsersService {
    Users saveUser(Users user) throws UserIsRegisteredException;

    Roles saveRole(Roles roles);

    void addRoleToUser(String usenrame, String roleName);

}
