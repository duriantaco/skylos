import importlib

MODEL_CLASSES = {
    "alpha": "plugpkg.models.alpha_model.AlphaModel",
    "beta": "plugpkg.models.beta_model:BetaModel",
    "gone": "retired.models.gamma_model.GammaModel",
}
UNUSED_CLASSES = {"delta": "plugpkg.models.delta_model.DeltaModel"}


def get_model_class(spec):
    full_path = MODEL_CLASSES.get(spec, spec)
    module_name, class_name = full_path.replace(":", ".").rsplit(".", 1)
    module = importlib.import_module(module_name)
    return getattr(module, class_name)
