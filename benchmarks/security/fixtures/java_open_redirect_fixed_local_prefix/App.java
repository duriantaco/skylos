import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
class App {
  @GetMapping("/owners/{id}/saved")
  String saved(@PathVariable String id) {
    return "redirect:/owners/" + id;
  }
}
