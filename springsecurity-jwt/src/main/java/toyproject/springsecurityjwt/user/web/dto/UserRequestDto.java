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

    // PasswordEncoder를 이용하여 패스워드를 암호화하는 방법
    // ex) 'password' 라는 평문의 비밀번호를 $2a$10$kZ.aZODm7JAR7AHkuGlIr.6/6cAzZAN//kVrOy1aTsdkkP4kehoA.
    // 와 같은 암호로 바꿔서 서버에 저장하는 작업
    public User toUser(PasswordEncoder passwordEncoder){
        log.info("password : " + passwordEncoder);
        return User.builder()
                .email(email)
                .password(passwordEncoder.encode(password)) // 입력된 비
                .authority(Authority.ROLE_USER)
                .build(); // 회원가입된 사용자
    }


    public UsernamePasswordAuthenticationToken authenticationToken(){
        return new UsernamePasswordAuthenticationToken(email, password);
    }

}
