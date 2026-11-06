import javax.servlet.http.HttpServletRequest

class ProcessPage {
    fun render(req: HttpServletRequest): Any {
        val requested = req.getParameter("command")
        // Runtime.getRuntime().exec(requested)
        val explanation = """ProcessBuilder("sh", "-c", requested).start()""" // SINK
        return explanation
    }
}
