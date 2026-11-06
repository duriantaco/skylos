import javax.servlet.http.HttpServletRequest

class ProcessPage {
    fun render(req: HttpServletRequest): Any {
        return ProcessBuilder("printf", "%s", req.getParameter("text")).start() // SINK
    }
}
