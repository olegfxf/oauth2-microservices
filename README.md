# oauth2-microservices

# InMemory authentication for microservices
В проекте исследуется работа oauth2 в микросервисной архитектуре.
Исходный текст проекта взят из статьи https://habr.com/ru/articles/701912/. UserDetailsService
определен в проекте как:
```java
    UserDetailsService users() {
        UserDetails user1 = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build();
        UserDetails user2 = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user1, user2);
    }
```
Контроллер в проекте один. Код контроллера:
```java
@RestController
public class ResourceController {
    @GetMapping("/resource")
    public String getResource() {
        return "Resource";
    }
}
```

Запуск и тестирование:\
Откроем браузер и перейдем по ссылке 127.0.0.1:8080/resource. Порт в URL указываем
принадлежащий Gateway серверу. После перехода по ссылке нас редиректит на форму
ввода логина и пароля:
```text
Login: user
Password: password
Output - Resource

Login: admin
Password: password
Output - Resource
```
Для пользователей user и admin ресурс "/resource" одинаково доступен, как и следовало ожидать,
так как авторизация не настроена.


# InMemory authorization for microservices
По умолчанию oauth2 не включает в сервер авторизации поддержку ролей. Это можно проверить
перехватив JWT. Так фильтр MyBasicAuthentificationFilter перехватывает токен и PAYLOAD токена
имеет вид:
```json
{
  "sub": "user",
  "aud": "gateway",
  "nbf": 1696351620,
  "scope": [
    "openid",
    "resource.read"
  ],
  "iss": "http://localhost:9000",
  "exp": 1696351920,
  "iat": 1696351620
}
```
Токен не содержит данные о ролях пользователя. Для поддержки ролей в публикации
"Add Roles to JWT Issued by Spring Authorization Server"
https://www.appsdeveloperblog.com/add-roles-to-jwt-issued-by-new-spring-authorization-server/
рекомендуют использовать бин:
```java
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (context.getTokenType() == OAuth2TokenType.ACCESS_TOKEN) {
                Authentication principal = context.getPrincipal();
                Set<String> authorities = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                context.getClaims().claim("roles", authorities);
            }
        };
    }
```
Конфигурация сервера ресурсов для поддержки авторизации по ролям изменяется.
Согласно рекомендациям "Role-based Access Control in Spring Authorization Server"
https://www.appsdeveloperblog.com/role-based-access-control-in-spring-authorization-server/
добавляются JwtAuthenticationConverter и JwtRoleConverter. В классе 
ResourceServerConfig изменяется securityFilterChain. Добавляется условие 
доступа к ресурсу - .antMatchers("/resource/**").hasRole("USER").
Только пользователь с ролью ROLE_USER имеет доступ к ресурсу "/resource".
Класс ResourceServerConfig приобретает вид:
```java
@EnableWebSecurity
public class ResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new JwtRoleConverter());

        http
                .authorizeRequests()
                .antMatchers("/resource/**")
                .access("hasAuthority('SCOPE_resource.read')")
                .antMatchers("/resource/**").hasRole("USER")
                .and()
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter);
        http.addFilterBefore(new MyBasicAuthentificationFilter(), BasicAuthenticationFilter.class);
        return http.build();
    }
```
Теперь PAYLOAD токена содержит данные о ролях пользователя:
```json
{
  "sub": "user",
  "aud": "gateway",
  "nbf": 1696350567,
  "scope": [
    "openid",
    "resource.read"
  ],
  "roles": [
    "ROLE_USER"
  ],
  "iss": "http://localhost:9000",
  "exp": 1696350867,
  "iat": 1696350567
}
```
Запуск и тестирование:\
Откроем браузер и перейдем по ссылке 127.0.0.1:8080/resource. Порт в URL указываем
принадлежащий Gateway серверу. После перехода по ссылке нас редиректит на форму
ввода логина и пароля:
```text
Login: user
Password: password
Output - Resource

Login: admin
Password: password
Output - Доступ к 127.0.0.1 запрещен
У вас нет прав для просмотра этой страницы.
HTTP ERROR 403
```
Пользователь user с ролью ROLE_USER прошел аутентификацию и авторизацию,
получил доступ к ресурсу "/resource". Пользователь admin имеет роль
ROLE_ADMIN. Он прошел аутентификацию, но не прошел авторизацию.






