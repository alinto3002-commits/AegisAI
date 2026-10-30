import pickle

def load_cached_report(serialized_data: bytes):
    # Insecure deserialization via pickle (CWE-502)
    return pickle.loads(serialized_data)

def export_report_state(report_obj, filepath: str):
    with open(filepath, "wb") as f:
        pickle.dump(report_obj, f)
