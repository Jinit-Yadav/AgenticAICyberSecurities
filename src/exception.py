import sys 
import logging
from src.logger import logging

def error_message_detail(error, error_detail: sys):
    """
    Extract detailed error information including filename and line number
    """
    try:
        # More robust way to get traceback
        _, _, exc_tb = error_detail.exc_info()
        if exc_tb is not None:
            file_name = exc_tb.tb_frame.f_code.co_filename
            line_number = exc_tb.tb_lineno
            error_message = f"CyberSec Error in [{file_name}] line [{line_number}]: {str(error)}"
        else:
            error_message = f"CyberSec Error: {str(error)}"
        
        return error_message
    except Exception as e:
        return f"Error formatting failed: {str(error)}, Format Error: {str(e)}"
class CustomException(Exception):
    def __init__(self, error_message, error_detail: sys):
        super().__init__(error_message)
        self.error_message = error_message_detail(error_message, error_detail=error_detail)
        # Log the error
        logging.error(self.error_message)

    def __str__(self):
        return self.error_message