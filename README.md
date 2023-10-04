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
так как авторизация не настроена. При успешном подключении к приложению формируется JWT. За время
действия JWT он не позволит подключится под другим логином. Для входа под другим логином требуется
перегрузить приложение.