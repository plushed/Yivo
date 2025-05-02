from .dispatch_table import MODULE_QUERIES
from .module_handlers import STANDARDIZERS, RISK_SCORERS
import logging

# Set up logging
logger = logging.getLogger(__name__)

def get_modules_for_type(indicator_type: str, enabled_modules: list[str]) -> list:
    """
    Filters the enabled modules based on the given indicator type and returns
    a list of modules that support the indicator type.
    """
    # Normalize the dispatch table for case-insensitive matching
    normalized_dispatch = {
        name.lower(): data for name, data in MODULE_QUERIES.items()
    }

    # Filter enabled modules that support the indicator type
    return [
        module for module in enabled_modules
        if module.lower() in normalized_dispatch and
           indicator_type in normalized_dispatch[module.lower()]['supported_types']
    ]

def route_query(user, indicator: str, indicator_type: str, enabled_modules: list[str]) -> dict:
    results = {}
    selected_modules = get_modules_for_type(indicator_type, enabled_modules)

    for module in selected_modules:
        try:
            normalized_module = module.lower()

            # Retrieve and instantiate the query class
            module_config = MODULE_QUERIES.get(module)
            if not module_config or 'class' not in module_config:
                raise KeyError(f"Module '{module}' is missing or misconfigured.")

            query_instance = module_config['class'](user)
            raw_result = query_instance.query(indicator)
                # Debugging: Print raw_result and its type to confirm its structure
            print("Raw result:", raw_result)
            print("Type of raw result:", type(raw_result))
            # Standardize results if a standardizer exists
            if normalized_module in STANDARDIZERS:
                standardized = STANDARDIZERS[normalized_module](raw_result, indicator)
                results[module] = standardized
            else:
                logger.warning(f"No standardizer registered for module '{module}'")
                results[module] = {
                    "error": "Standardizer not available for this module.",
                    "raw": raw_result
                }

        except KeyError as e:
            logger.error(f"[{module}] KeyError: {e}")
            results[module] = {
                "error": f"Configuration error for module '{module}': {e}"
            }

        except Exception as e:
            logger.exception(f"[{module}] Unexpected error during query execution.")
            results[module] = {
                "error": f"Failed to query module '{module}': {str(e)}"
            }
    logger.debug(f"Results after processing modules: {results}")

    return results