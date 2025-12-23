import ast
import operator

OPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
    ast.In: lambda x, y: x in y,
    ast.NotIn: lambda x, y: x not in y,
}


def evaluate_static_condition(node):
    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        val = evaluate_static_condition(node.operand)
        if val is not None:
            return not val
        else:
            return None

    if isinstance(node, ast.BoolOp):
        values = []
        for v in node.values:
            values.append(evaluate_static_condition(v))

        if isinstance(node.op, ast.And):
            for v in values:
                if v is False:
                    return False

            for v in values:
                if v is None:
                    return None

            return True

        if isinstance(node.op, ast.Or):
            for v in values:
                if v is True:
                    return True

            for v in values:
                if v is None:
                    return None

            return False

    if isinstance(node, ast.Compare):
        if len(node.ops) == 1 and len(node.comparators) == 1:
            left = evaluate_static_condition(node.left)
            right = evaluate_static_condition(node.comparators[0])
            op_type = type(node.ops[0])

            if left is not None and right is not None and op_type in OPS:
                try:
                    return OPS[op_type](left, right)
                except Exception:
                    return None

    return None


def extract_constant_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None
