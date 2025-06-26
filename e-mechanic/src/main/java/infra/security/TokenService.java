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

@Service
public class TokenService {

    // A variavel secret está sendo criada e a partir do @Value está pegand uma informção do application.properties
    @Value("${api.security.token.secret}")
    private String secret;


    public String generateToken(User user){
        try {
            // Está criado a chave de algoritimo hash
            Algorithm algorithm = Algorithm.HMAC256(secret);

            //gerando Token
            String token = JWT.create()
                    // Qual micro serviço está gerando o token
                    .withIssuer("login-auth-api")
                    // Quem está recebendo esse token
                    .withSubject(user.getEmail())
                    // Tempo em que expira o token
                    .withExpiresAt(this.generateExpirationDate())
                    //passando algoritimo par aefetivamente gerar o token
                    .sign(algorithm);
                return token;
        } catch (JWTCreationException exception){
            throw   new RuntimeException("Error while authenticating");
        }
    }

    public String validateToken(String token){
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                    .withIssuer("login-auth-api")
                    .build()
                    .verify(token)
                    .getSubject();

        } catch (JWTVerificationException exception){
            return null;
        }
    }

    //Gera o tempo de expiração de um token
    private Instant generateExpirationDate(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
