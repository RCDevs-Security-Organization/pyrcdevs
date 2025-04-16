import traceback


def get_full_exception_msg(excinfo):
    return ''.join(traceback.format_exception(type(excinfo.value), excinfo.value, excinfo.tb))
