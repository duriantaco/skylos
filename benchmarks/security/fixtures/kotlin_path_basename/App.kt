import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class DocumentPage {
    @GetMapping("/document")
    fun read(@RequestParam name: String): String {
        return java.io.File("/srv/catalogue", java.io.File(name).name).readText() // SINK
    }
}
