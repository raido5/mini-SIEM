import pandas as pd
import csv 

SENSITIVE_PATHS = ["/admin", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin", "/backup.zip", "/config.php"]

LABELS = {
    "192.168.1.10": "normal",
    "192.168.1.11": "normal",
    "192.168.1.12": "normal",
    "45.12.88.10": "brute_force",
    "91.44.20.7": "possible_compromise",
    "45.13.99.20": "brute_force",
    "203.0.113.55": "web_scan",
    "66.77.88.99": "possible_compromise",
}

def build_features(input_path,output_path):
    df= pd.read_csv(input_path)

    features=[]

    for ip,group in df.groupby("ip"):
        http=group[group["source"]=="http"]
        nbr_http= len(http)
        nbr_404= len(http[http["status_code"]==404])
        ratio_404= nbr_404/nbr_http if nbr_http>0 else 0.0 

        ligne ={"ip" :ip,
                "failed_logins": len(group[group["status"]=="failed"]),
                "success_logins" : len(group[group["status"]=="success"]),
                "unique_users" : group["user"].nunique(),
                "http_requests": len(group[group["source"]=="http"]),
                "unique_paths" : group["path"].nunique(),
                "ratio_404" : ratio_404,
                "sensitive_paths":len(group[group["path"].isin(SENSITIVE_PATHS)]),
                "label":LABELS[ip]
                                }
        features.append(ligne)
    
    write_csv(features, output_path)

def write_csv(features, output_path):
    colonnes = ["ip", "failed_logins", "success_logins", "unique_users",
                "http_requests", "unique_paths", "ratio_404", "sensitive_paths", "label"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=colonnes)
        writer.writeheader()
        for ligne in features:
            writer.writerow(ligne)
        
if __name__ == "__main__":
    build_features("data/interim/parsed_events.csv", "data/processed/features_v1.csv")


