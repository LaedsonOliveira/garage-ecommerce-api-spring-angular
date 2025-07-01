package controller;

import domain.user.AuthenticationDTO;
import domain.user.RegisterDTO;
import domain.user.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import repository.UserRepository;

@RestController
@RequestMapping("auth")
public class AutenticationController {

    //Essa classe e fornecida pelo SPRing Boot Para fazer a autenticacao
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository repository;


    @PostMapping("/login")
    // metodo publico que retorna um ResponseEntity, recebe informacoes do body json, DTO sao os dados que vem do cliente pelo body
    public ResponseEntity login(@RequestBody @Validated AuthenticationDTO data){
        //Precisa criar um hash de login para nao colocar diretamente as informacoes de login
        var usernamePassword = new UsernamePasswordAuthenticationToken(data.login(), data.password());
        //e necessario autenticar o usuario e senha
        var auth = this.authenticationManager.authenticate(usernamePassword);

        //Vai retornar
        return ResponseEntity.ok().build();
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody @Validated RegisterDTO data){
        //vai procurar dentro do banco de dados(repository) algum login, se encontrar algo retorne badRequest
        if(this.repository.findByLogin(data.login()) != null ) return ResponseEntity.badRequest().build();

        //a variavel vai receber a senha do DTO para criptografar com encode
        String encryptedPassword = new BCryptPasswordEncoder().encode(data.password());
        User newUser = new User(data.login(), data.password(), data.role());

        this.repository.save(newUser);

        return ResponseEntity.ok().build();
    }

}
