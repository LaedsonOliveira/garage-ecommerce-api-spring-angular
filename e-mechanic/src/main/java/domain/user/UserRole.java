package domain.user;

//classes enum sao usadas para definir valores e funcoes que nao se alteram
public enum UserRole {
    ADMIN("admin"),
    USER("user");

    private String role;

    UserRole(String role){
        this.role = role;
    }

    public String getRole() {
        return role;
    }
}
