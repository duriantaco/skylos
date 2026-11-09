import javax.servlet.http.HttpServletRequest

class ProcessPage {
    fun render(req: HttpServletRequest): Any {
        return ProcessBuilder("printf", "%d", req.getParameter("number").toInt().toString()).start() // SINK
    }
}
