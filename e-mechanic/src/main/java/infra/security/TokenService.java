package infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import domain.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

//Pedir para a ia explicar melhor

@Service
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;

    //Depois que o usuario fizer a requisicao e mandar o token, precisamos ver quem e e ver ser ele tem a role necessaria para a requisicao
    public String generateToken(User user){
        try{
            Algorithm algorithm = Algorithm.HMAC256(secret);
            //criando a variavel token que recebe uma reacao do JWT
            String token = JWT.create()
                    //Quem emitiu / quem criou o token
                    .withIssuer("auth-api")
                    //O usuario que esta recebendo
                    .withSubject(user.getLogin())
                    //Data de expiracao
                    .withExpiresAt(genExpirationDate())

                    .sign(algorithm);
            return token;

        } catch (JWTCreationException exception){
            throw new RuntimeException("Erro while generating token", exception);
        }
    }

    public String validateToken(String token){
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                    .withIssuer("auth-api")
                    //Montando novamente o dado que esta ali dentro
                    .build()
                    //Descriptografica o token
                    .verify(token)
                    //Pegou o subject(usuario)
                    .getSubject();

        } catch (JWTVerificationException exception){
            return "";

        }
    }

    //Definir  tempo de expiracao para o withExpirestAt
    private Instant genExpirationDate(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
