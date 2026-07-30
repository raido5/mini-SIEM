import pandas as pd
from sklearn.model_selection import train_test_split

def load_dataset(path):
    df = pd.read_csv(path)
    if df.empty:
        raise ValueError("Le fichier CSV est vide.")
    return df

def split_features_target(df, target_col="label"):
    y = df[target_col]
    X = df.drop(columns=["ip", target_col])
    return X, y

def make_train_test_split(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    return X_train, X_test, y_train, y_test