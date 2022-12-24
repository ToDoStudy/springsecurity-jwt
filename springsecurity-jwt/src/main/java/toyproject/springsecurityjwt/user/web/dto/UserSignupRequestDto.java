package toyproject.springsecurityjwt.user.web.dto;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import toyproject.springsecurityjwt.user.Authority;
import toyproject.springsecurityjwt.user.User;

@Slf4j
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class UserSignupRequestDto {

    private String email;
    private String password;
    private int auth; // 0이라면 : admin, 1이라면 : user

    // PasswordEncoder를 이용하여 패스워드를 암호화하는 방법
    // ex) 'password' 라는 평문의 비밀번호를 $2a$10$kZ.aZODm7JAR7AHkuGlIr.6/6cAzZAN//kVrOy1aTsdkkP4kehoA.
    // 와 같은 암호로 바꿔서 서버에 저장하는 작업
    public User toUser(PasswordEncoder passwordEncoder){
        log.info("password : " + passwordEncoder);
        Authority authRes;
        if(auth == 1) authRes = Authority.ROLE_USER; // 사용자
        else authRes = Authority.ROLE_ADMIN; // 관리자

        return User.builder()
                .email(email)
                .password(passwordEncoder.encode(password)) // 입력된 비
                .authority(authRes)
                .build(); // 회원가입된 사용자
    }

}