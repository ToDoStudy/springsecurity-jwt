package toyproject.springsecurityjwt.tokenjwt;

import toyproject.springsecurityjwt.tokenjwt.dto.TokenDto;
import toyproject.springsecurityjwt.tokenjwt.dto.TokenRequestDto;
import toyproject.springsecurityjwt.user.web.dto.UserRequestDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class TokenService {

    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    private final JwtTokenProvider jwtTokenProvider;

    private final RefreshTokenRepository refreshTokenRepository;

    // 로그인
    @Transactional
    public TokenDto login(UserRequestDto userRequestDto){

        // UsernamePasswordAuthenticationToken 형태로 리턴, SecurityContext 를 사용하기 위한 절차
        // 라이브러리에 있는 것 사용
        // 현재 입력된 아이디, 패스워드를 통해 token을 발급받는다.
        // UsernamePasswordAuthenticationToken
        // - 첫 번째 생성자는 인증 전의 객체를 생성하고
        // - 두 번째 생성자는 인증이 완료된 객체를 생성한다.
        UsernamePasswordAuthenticationToken authenticationToken = userRequestDto.authenticationToken();


        // 비밀번호 체크
        // authenticate 메서드가 실행이 될 때 CustomUserDetailsService 에서 만들었던 loadUserByUsername 메서드가 실행됨
        // loadUserByUsername
        // Authentication : 인증
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 인증 정보를 통해 JWT 토큰을 생성한다.
        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(authentication);

        // RefreshToken 저장
        RefreshToken refreshToken = RefreshToken.builder()
                .key(authentication.getName())
                .value(tokenDto.getRefreshToken())
                .build();

        refreshTokenRepository.save(refreshToken);

        // 토큰 발급
        return tokenDto;
    }


    // 토큰 재발급
    @Transactional
    public TokenDto reissue(TokenRequestDto tokenRequestDto){
        // Refresh Token 검증
        if(!jwtTokenProvider.validateToken(tokenRequestDto.getRefreshToken())){
            throw new RuntimeException("Refresh Token이 유효하지 않습니다.");
        }

        // Access Token에서 User ID 가져오기
        Authentication authentication = jwtTokenProvider.getAuthentication(tokenRequestDto.getAccessToken());

        // 저장소에서 User ID를 기반으로 Refresh Token 값 가져오기
        RefreshToken refreshToken = refreshTokenRepository.findByKey(authentication.getName())
                .orElseThrow(() -> new RuntimeException("로그아웃 된 사용자입니다."));

        // Refresh Token 일치하는지 검사
        if(!refreshToken.getValue().equals(tokenRequestDto.getRefreshToken())){
            throw new RuntimeException("토큰의 유저 정보가 일치하지 않습니다.");
        }

        // 새로운 토큰 생성
        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(authentication);

        // 저장소 정보 업데이트
        RefreshToken newRefreshToken = refreshToken.updateValue(tokenDto.getRefreshToken());
        refreshTokenRepository.save(newRefreshToken);

        // 토큰 발급
        return tokenDto;
    }
}
