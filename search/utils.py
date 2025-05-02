def normalize_module_name(name: str) -> str:
    return name.lower().replace(" ", "").replace("-", "").replace("_", "")

def calculate_overall_risk_score(module_scores, user_module_weights):
    """
    Calculate the overall risk score based on module scores and user-specific module weights.
    """
    overall_score = 0
    total_weight = 0

    for module_name, score in module_scores.items():
        weight = user_module_weights.get(module_name, 0)
        overall_score += score * weight
        total_weight += weight

    if total_weight > 0:
        overall_score /= total_weight
    return round(overall_score, 2)  # Assuming you want a floating-point result