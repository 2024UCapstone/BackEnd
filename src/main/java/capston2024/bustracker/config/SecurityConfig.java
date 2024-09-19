package capston2024.bustracker.config;

import capston2024.bustracker.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
@Slf4j
public class SecurityConfig {
    private final AuthService authService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)  // API 서버라면 비활성화, 웹 애플리케이션이라면 활성화 고려
                .cors(withDefaults())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/private/**").authenticated() // "/private/**"로 시작하는 URI는 인증 필요
                        .anyRequest().permitAll() // 나머지 URI는 모두 접근 허용
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/api/auth/login") // 로그인 페이지 설정
                        .defaultSuccessUrl("/") // 로그인 성공 시 이동할 페이지
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(authService)
                        )
                );

        return http.build();
    }
}
