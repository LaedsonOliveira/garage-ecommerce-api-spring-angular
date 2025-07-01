package repository;

import domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

//Repositories serve para conectar ao banco de dados (JPA)
public interface UserRepository extends JpaRepository<User, String> {
    //Essa funcao que esta em uma interface retorna um UserDetails, buscando pelo login
    UserDetails findByLogin(String login);
}
