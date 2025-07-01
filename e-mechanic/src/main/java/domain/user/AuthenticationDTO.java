package domain.user;

//Sao as informacoes que vem do cliente do body, login e senha
public record AuthenticationDTO(String login, String password) {
}
