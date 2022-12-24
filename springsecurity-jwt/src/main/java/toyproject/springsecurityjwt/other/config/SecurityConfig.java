package toyproject.springsecurityjwt.other.config;

import toyproject.springsecurityjwt.tokenjwt.JwtTokenProvider;
import toyproject.springsecurityjwt.tokenjwt.error.JwtAccessDeniedHandler;
import toyproject.springsecurityjwt.tokenjwt.error.JwtAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {


    // JwtTokenProvider SecurityConfig 설정 추가
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    // DB 에 있는 값은 암호화된 값이고 사용자가 입력한 값은 raw 값이지만 passwordEncoder가 알아서 비교해준다.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // CSRF 설정 Disable
        http.csrf().disable()
                // exception handling할 때 만든 클래스들을 추가한다.
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // 시큐리는 기본적으로 세션을 사용
                // 여기서는 세션을 사용하지 않기 때문에 세션 설정을 Stateless로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                // 로그인, 회원가입 API는 토큰이 없는 상태에서 요청이 들어오기 때문에 permitAll(접근 가능하게)
                .and()
                .authorizeRequests()
                .antMatchers("/user/login", "/user/signup", "/user/reissue").permitAll()
                .anyRequest().authenticated() // 나머지 API는 전부 인증 필요하다.

                // JwtFilter를 addFilterBefore로 등록했던 JwtSecurityConfig 클래스를 적용한다.
                .and()
                .apply(new JwtSecurityConfig(jwtTokenProvider));


        return http.build();
    }


}
