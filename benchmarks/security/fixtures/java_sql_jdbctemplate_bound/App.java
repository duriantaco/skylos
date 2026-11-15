import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class App {
  private final JdbcTemplate jdbcTemplate;

  App(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @GetMapping("/users")
  List<Map<String, Object>> users(@RequestParam String name) {
    return jdbcTemplate.queryForList("SELECT id FROM users WHERE name = ?", name);
  }
}
