package infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import repository.UserRepository;

import java.io.IOException;

// pedir para a ia explicar codigo

@Component
//Classe de Filtros que esta no SecurityConfiguration
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    //injeta essa classe para conseguir fazer as validacoes de token
    TokenService tokenService;
    @Autowired
    //usado para encontrar o usuario a partir do login
    UserRepository userRepository;

    @Override
    //Esse e o filtro que vai ser chamado
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //Esta sendo passado o request par a variavel token, o metodo esta sendo criado abaixo
        var token = this.recoverToken(request);
        //ja pega a informacao se o token e nulo, por isso token != null
        if(token != null){
            //valida token
            var login = tokenService.validateToken(token);
            //pega o usuario a partir de login
            UserDetails user = userRepository.findByLogin(login);

            var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        //Chama o proximo filtro, pois nao encontrou nada
        filterChain.doFilter(request, response);
    }

    //Pega as informacoesdo request
    private String recoverToken(HttpServletRequest request){
        var authHeader = request.getHeader("Authorization");
        if(authHeader == null) return null;
        //Bearer e um tipo de token, isso e feito para pegar apenas o token, sem o nome "bearer"
        return authHeader.replace("Bearer","");
    }
}
