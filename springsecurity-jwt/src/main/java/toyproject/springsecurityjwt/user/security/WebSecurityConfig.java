package toyproject.springsecurityjwt.user.security;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig{
    // Configuration : 설정파일을 만들기 위한 애노테이션 or Bean을 등록하기 위한 애노테이션

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        log.info("log : " + authenticationConfiguration.toString());
        return authenticationConfiguration.getAuthenticationManager();
    }

}
