import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class Catalogue(private val jdbc: JdbcTemplate) {
    @GetMapping("/catalogue")
    fun search(@RequestParam term: String, @RequestParam page: String): Any {
        return jdbc.queryForList("SELECT * FROM catalogue WHERE label = '$term'") // SINK
    }
}
