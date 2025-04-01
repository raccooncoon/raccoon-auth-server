# Raccoon Auth Server

Keycloak 수준의 Spring Boot + JWT 인증 시스템 템플릿

✅ 포함된 주요 클래스

파일	설명
AuthServerApplication.java	스프링 부트 메인 클래스
User.java	사용자 도메인 (username, email, role 등)
UserRepository.java	사용자 조회 JPA 레포지토리
LoginRequest.java, SignupRequest.java	로그인/회원가입 DTO
TokenResponse.java	Access + Refresh Token 응답 DTO
JwtService.java	JWT 발급, 검증, 파싱 로직 포함 (Keycloak 수준)