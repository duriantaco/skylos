from sqlalchemy.ext.hybrid import hybrid_property


class User:
    @hybrid_property
    def full_name(self):
        return "Ada"
