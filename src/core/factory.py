from src.core.state_manager import SecurityStateManager

def create_detector(detector_class, state_manager=None):
    """
    Factory function to create detectors with proper state manager injection.
    """
    sm = state_manager or SecurityStateManager()
    return detector_class(state_manager=sm)
