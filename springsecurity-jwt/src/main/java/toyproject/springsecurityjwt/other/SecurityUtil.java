package toyproject.springsecurityjwt.other;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Slf4j
public class SecurityUtil {

    private SecurityUtil() {}

    // SecurityContext에 유저 정보가 저장되는 시점
    // Request가 들어올 때 JwtFilter의 doFilter에서 저장
    public static Long getCurrentMemberId(){
        // getCurrentMemberId : Security Context의 Authentication 객체를 이용해 username을 리턴해주는 간단한 유틸성 메소드이다.
        // Authentication 객체가 저장되는 시점 : JwtFilter의 doFilter 메소드에서 Request가 들어올 때 SecurityContext에
        // Authentication 객체를 저장해서 사용하게 된다.
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authentication == null || authentication.getName() == null){
            log.info("Security Context에 인증 정보가 없습니다.");
            throw new RuntimeException("Security Context에 인증 정보가 없다.");
        }

        return Long.parseLong(authentication.getName());
    }
}
