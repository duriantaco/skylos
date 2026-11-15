package app

class Idle {
    fun size(wrapper: Wrapper): Int {
        if (wrapper.inner == null) {
            return 0
        }
        return 1
    }

    private fun Wrapper.unwrapAll(): Int = 0
}
