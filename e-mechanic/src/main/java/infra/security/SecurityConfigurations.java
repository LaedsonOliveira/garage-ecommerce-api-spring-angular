package infra.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.concurrent.ExecutionException;

@Configuration
@EnableWebSecurity
public class SecurityConfigurations {

    //Serve para que o SB consiga instanciar a classe
    @Bean
    //Corrente de filtros de seguraca                                         //Trata exescao
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                // o csrf previne contra ataques em autenticacao statefull, porem em statleless e redundante, pois ja
                // e realizada essa atividade
                .csrf(csrf -> csrf.disable())
                //esta habilitando o statless, para passar autorizacao por tokens/session
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //Como authorizeHttpRequest posso descrever qual vai ser a regra de altenticacao, no caso, qualquer
                // requisicao post para o endpoint /product e necessario a ADMIN
                .authorizeHttpRequests(authorize -> authorize
                        //Qualquer pessoa pode ter acesso ao endpoint /auth/login
                        .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/product").hasRole("ADMIN")
                        //Para qualquer outro request so e necessario que seja autenticado, nao precisa de role
                        .anyRequest().authenticated()
                )
                //Criar o objeto
                .build();
    }

    //Esta sobescrevendo o AutenticationManager para trazer as informacoes que deseja
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        //pega somente a instancia do auntheticationManager
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    //Criptografa as senhas para um hash
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
