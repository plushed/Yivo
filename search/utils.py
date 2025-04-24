def normalize_module_name(name: str) -> str:
    return name.lower().replace(" ", "").replace("-", "").replace("_", "")