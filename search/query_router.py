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
    logger.debug(f"Arguments received - user: {user}, indicator: {indicator}, indicator_type: {indicator_type}, enabled_modules: {enabled_modules}")
    results = {}
    selected_modules = get_modules_for_type(indicator_type, enabled_modules)

    for module in selected_modules:
        try:
            query_class = MODULE_QUERIES[module]['class']
            query_instance = query_class(user)
            raw_result = query_instance.query(indicator)

            # Use standardizer
            if module in STANDARDIZERS:
                standardized = STANDARDIZERS[module](raw_result, indicator)

                results[module] = standardized
            else:
                logger.warning(f"No standardizer found for module: {module}")
                results[module] = {"error": "No standardizer found", "raw": raw_result}

        except KeyError as e:
            logger.error(f"Module '{module}' or its class is not found in MODULE_QUERIES: {e}")
            results[module] = {'error': f"Module '{module}' not found or improperly configured."}
        
        except Exception as e:
            logger.error(f"Error executing query for {module}: {str(e)}")
            results[module] = {'error': str(e)}

    return results