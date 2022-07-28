package id.codecorn.autorizationserver.entity;

import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.Entity;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Data;
import static javax.persistence.FetchType.EAGER;

@Data
@Entity
@Table(name = "t_users")
public class Users extends BaseEntity {
	private String username;
	private String email;

	@JsonIgnore
	private String password;
	private String noHp;
	private Boolean active;

	@ManyToMany(fetch = EAGER)
	private Collection<Roles> roles = new ArrayList<>();

}
