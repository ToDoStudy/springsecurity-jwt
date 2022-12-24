
# 📚 1. JWT 관련 설정

  
### 📖 A. JwtTokenProvider

  

```java

@Slf4j

@Component

public class JwtTokenProvider {

  

// 이 클래스에서

// - 유저 정보로 JWT 토큰을 만들거나 토큰을 바탕으로 유저 정보를 가져온다.

// - JWT 토큰에 관련된 암호화, 복호화, 검증 로직은 다 이곳에서 이루어진다.

  

// bean 직접 생성

private static final String AUTHORITIES_KEY = "auth";

private static final String BEARER_TYPE = "Bearer";

private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30; // 30분

private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 7; // 7일

  

private final Key key;

  

// application.yml 에 정의해놓은 jwt.secret 값을 가져와서 JWT 를 만들 때 사용하는 암호화 키값을 생성

public JwtTokenProvider(@Value("${spring.jwt.secret}") String secretKey){

byte[] keyBytes = Decoders.BASE64.decode(secretKey);

this.key = Keys.hmacShaKeyFor(keyBytes);

}

  

// 유저 정보를 넘겨받아서 Access Token 과 Refresh Token을 생성

public TokenDto generateTokenDto(Authentication authentication){

// 권한들을 가져오기

String authorities = authentication.getAuthorities().stream()

.map(GrantedAuthority::getAuthority)

.collect(Collectors.joining(","));

  

long now = (new Date()).getTime(); // 현재 시간

  

// Access Token을 생성한다.

Date accessTokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);

String accessToken = Jwts.builder()

.setSubject(authentication.getName()) // payload "sub": "name"

.claim(AUTHORITIES_KEY, authorities) // payload "auth": "ROLE_USER"

.setExpiration(accessTokenExpiresIn) // payload "exp": 1516239022 (예시)

.signWith(key, SignatureAlgorithm.HS512) // header "alg": "HS512"

.compact();

  

// Refresh Token 생성

String refreshToken = Jwts.builder()

.setExpiration(new Date(now + REFRESH_TOKEN_EXPIRE_TIME))

.signWith(key, SignatureAlgorithm.HS512)

.compact();

  

return TokenDto.builder()

.grantType(BEARER_TYPE)

.accessToken(accessToken)

.accessTokenExpiresIn(accessTokenExpiresIn.getTime()) // 만료시간

.refreshToken(refreshToken)

.build();

}

}

```

  

- 생성자에서는 ?

	- `application.yml` 에 정의해놓은 `jwt.secret` 값을 가져와서 JWT 를 만들 때 사용하는 암호화 키값을 생성한다.

- `generateTokenDto`에서는 ? JWT 토큰에 관련된 **암호화**

	- 유저 정보를 넘겨받아서 **Access Token 과 Refresh Token 을 생성한다.**

	- 넘겨받은 유저 정보의 `authentication.getName()` 메소드가 `username` 을 가져온다.

	- `username` 으로 user ID 를 저장했기 때문에 해당 값이 설정된다.

	- Access Token 에는 유저와 권한 정보를 담고 Refresh Token 에는 아무 정보도 담지 않는다.

- `getAuthentication`

	- JWT 토큰을 복호화하여 토큰에 들어 있는 정보를 꺼낸다.

	- Access Token 에만 유저 정보를 담기 때문에 명시적으로 `accessToken` 을 파라미터로 받는다.

	- Refresh Token 에는 아무런 정보 없이 만료일자만 담았다.

	- `UserDetails` 객체를 생생성해서 `UsernamePasswordAuthenticationToken` 형태로 리턴하는데 `SecurityContext` 를 사용하기 위한 절차다.

	- 사실 좀 불필요한 절차라고 생각되지만 `SecurityContext` 가 `Authentication` 객체를 저장하기 때문에 어쩔수 없다.

	- `parseClaims` 메소드는 만료된 토큰이어도 정보를 꺼내기 위해서 따로 분리했다.

- `validateToken`

	- 토큰 정보를 검증한다.

	- `Jwts` 모듈이 알아서 Exception 을 던져준다.

  

⇒ JWT 토큰에 관련된 **암호화, 복호화, 검증 로직**은 다 이곳에서 이루어진다.


&nbsp;


**✍🏻 TokenDto는 어떤 것일까?**

  

```java

@Getter

@NoArgsConstructor

@AllArgsConstructor

@Builder

public class TokenDto {

  

private String grantType; // 고객

private String accessToken;

private String refreshToken;

private Long accessTokenExpiresIn; // 액세스 토큰 만료기간

}

```

&nbsp;


### **📖 B. JwtFilter**

  

```java

@RequiredArgsConstructor

public class JwtFilter extends OncePerRequestFilter {

  

public static final String AUTHORIZATION_HEADER = "Authorization";

public static final String BEARER_PREFIX = "Bearer ";

  

private final JwtTokenProvider jwtTokenProvider;

  

// 실제 필터링 로직은 doFilterInternal에 들어간다.

// JWT 토큰의 인증 정보를 현재 쓰레드의 SecurityContext에 저장하는 역할을 수행한다.

@Override

protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

  

// (1) Request Header에서 토큰을 꺼낸다.

String jwt = resolveToken(request);

  

// (2) validateToken으로 토큰 유효성 검사

// 정상 토큰이면 해당 토큰으로 Authentication을 가져와서 SecurityContext에 저장

if(StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)){

Authentication authentication = jwtTokenProvider.getAuthentication(jwt);

SecurityContextHolder.getContext().setAuthentication(authentication);

}

  

filterChain.doFilter(request, response);

}

  

// Request Header 에서 토큰 정보를 꺼내오기

private String resolveToken(HttpServletRequest request){

String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

if(StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)){

return bearerToken.substring(7);

}

return null;

}

}

```

  

- `OncePerRequestFilter` 인터페이스를 구현하기 때문에 요청 받을 때 단 한번만 실행된다.

- `doFilterInternal`

	- 실제 필터링 로직을 수행하는 곳이다.

	- Request Header 에서 Access Token 을 꺼내고 여러가지 검사 후 유저 정보를 꺼내서 `SecurityContext` 에 저장한다.

	- 가입/로그인/재발급을 제외한 모든 Request 요청은 이 필터를 거치기 때문에 토큰 정보가 없거나 유효하지 않으면 정상적으로 수행되지 않는다.

	- 그리고 요청이 정상적으로 Controller 까지 도착했다면 `SecurityContext` 에 Member ID 가 존재한다는 것이 보장된다.

	- 대신 직접 DB 를 조회한 것이 아니라 Access Token 에 있는 Member ID 를 꺼낸 거라서, 탈퇴로 인해 Member ID 가 DB 에 없는 경우 등 예외 상황은 Service 단에서 고려해야 한다.



&nbsp;

&nbsp;


# 📚 2. Spring Security 관련 설정

  

### 📖 A. JwtSecurityConfig

  

```java

@RequiredArgsConstructor

public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

private final JwtTokenProvider jwtTokenProvider;

  

// JwtTokenProvider를 주입받아서 JwtFilter를 통해 Security 로직에 필터를 등록

@Override

public void configure(HttpSecurity builder) throws Exception {

JwtFilter customFilter = new JwtFilter(jwtTokenProvider);

builder.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);

}

}

```

  

- `SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>` 인터페이스를 구현하는 구현체이다.

- **여기서 직접 만든 `JwtFilter` 를 `Security Filter` 앞에 추가한다.**


&nbsp;

### 📖 B. **JwtAuthenticationEntryPoint**

  

```java

@Component

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

  

@Override

public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

// 유효한 자격증명을 제공하지 않고 접근하려고 할 때 401

response.sendError(HttpServletResponse.SC_UNAUTHORIZED);

}

}

```

  

- **유저 정보 없이 접근하면** `SC_UNAUTHORIZED (401)` 응답을 내려준다.

- `AuthenticationEntryPoint` : 인증 처리 과정에서 예외가 발생한 경우 예외를 핸들링하는 인터페이스이다. (인증이 되지 않은 유저가 요청을 했을 때 동작한다.)


&nbsp;

### 📖 C. **JwtAccessDeniedHandler**

  

```java

@Component

public class JwtAccessDeniedHandler implements AccessDeniedHandler {

@Override

public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {

// 필요한 권한이 없어 접근하려 할 때는 403

response.sendError(HttpServletResponse.SC_FORBIDDEN);

}

}

```

  

- **유저 정보는 있으나 자원에 접근할 수 있는 권한이 없는 경우** `SC_FORBIDDEN (403)` 응답을 내려준다.

- `AccessDeniedHandler` : 서버에 요청을 할 때 액세스가 가능한지 권한을 체크후 액세스 할 수 없는 요청을 했을때 동작한다.


&nbsp;

### 📖 D. SecurityConfig

  

```java

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

```

  

- **Spring 기반의 애플리케이션의 보안(인증과 권한, 인가 등)을 담당하는 스프링 하위 프레임워크이다.**

- **`Spring Security`는 '인증'과 '권한'에 대한 부분을 Filter 흐름에 따라 처리하고 있다.**

- `Spring Security` 의 가장 기본적인 설정이며 JWT 를 사용하지 않더라도 이 설정은 기본으로 들어간다.

- 또한, Spring Security 의 `WebSecurityConfigurerAdapter`가 deprecated 되어 이전 버전과 다르게 `extends WebSecurityConfigurerAdapter` 를 설정할 필요가 없다. (참고 : [https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter](https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter))


&nbsp;


### 📖 E. SecurityUtil

  

```java

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

throw new RuntimeException("Security Context에 인증 정보가 없다.");

}

  

return Long.parseLong(authentication.getName());

}

}

```

  

- `JwtFilter` 에서 `SecurityContext`에 세팅한 유저 정보를 꺼낸다.

- `userId` 를 저장하게 했으므로 꺼내서 Long 타입으로 파싱하여 반환한다.

- `SecurityContext` 는 `ThreadLocal` 에 사용자의 정보를 저장한다.


&nbsp;

&nbsp;

----

참고 자료

- [Spring Security 와 JWT 겉핥기](https://bcp0109.tistory.com/301)

- [[Spring Security] 스프링시큐리티의 기본 개념과 구조](https://devuna.tistory.com/55)


