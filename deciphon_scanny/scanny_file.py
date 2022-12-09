import importlib.resources

__all__ = ["scanny_file"]


def scanny_file():
    t = importlib.resources.files("deciphon_scanny").joinpath("scanny-mac")
    return importlib.resources.as_file(t)
