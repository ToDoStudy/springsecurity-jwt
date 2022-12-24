package toyproject.springsecurityjwt.user.web.dto;


import toyproject.springsecurityjwt.user.Authority;
import toyproject.springsecurityjwt.user.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class UserRequestDto {

    private String email;
    private String password;

    public UsernamePasswordAuthenticationToken authenticationToken(){
        return new UsernamePasswordAuthenticationToken(email, password);
    }

}
