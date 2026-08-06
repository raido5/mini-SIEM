import pandas as pd

SENSITIVE_PATHS = ["/admin", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin", "/backup.zip", "/config.php"]

def predict_rule(features):

    success_logins = features.get("success_logins", 0)
    failed_logins = features.get("failed_logins", 0)
    sensitive_paths = features.get("sensitive_paths", 0)
    ratio_404 = features.get("ratio_404", 0.0)

    SEUIL_ECHECS = 3
    SEUIL_RATIO_404 = 0.8  


    if (success_logins >= 1 and failed_logins >= SEUIL_ECHECS) or \
       (sensitive_paths >= 1 and ratio_404 < 1.0):
        return "possible_compromise"

    if sensitive_paths >= 1 and ratio_404 >= SEUIL_RATIO_404:
        return "web_scan"

    if failed_logins >= SEUIL_ECHECS and success_logins == 0:
        return "brute_force"

    return "normal"


def predict_all(input_path):
    df = pd.read_csv(input_path)
    predictions = []
    for _, row in df.iterrows():           
        features = row.to_dict()           
        label = predict_rule(features)     
        predictions.append({"ip": features["ip"], "predicted": label})
    return predictions


if __name__ == "__main__":
    resultats = predict_all("data/processed/features_v1.csv")
    for r in resultats:
        print(r)